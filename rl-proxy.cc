#include <netdb.h>
#include <memory>

#include "ten/app.hh"
#include "ten/buffer.hh"
#include "ten/http/server.hh"
#include "ten/json.hh"
#include "ten/shared_pool.hh"
#include <boost/lexical_cast.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>

#include "keygen.hh"
#include "credit-client.hh"

using namespace ten;
const size_t default_stacksize=256*1024;

struct proxy_config : app_config {
    std::string backend_host;
    unsigned short backend_port;
    std::string db;
    std::string db_host;
    std::string db_user;
    std::string credit_server_host;
    uint16_t credit_server_port;
    std::string listen_address;
    unsigned short listen_port;
    unsigned int credit_limit;
    std::string vhost;
    bool use_xff; // ok to trust X-Forwarded-For header
    std::string reset_duration_string;
    std::string secret;
    boost::posix_time::time_duration reset_duration;
};

static void host2addresses(std::string &host, uint16_t port, std::vector<address> &addrs) {
    struct addrinfo *results = 0;
    struct addrinfo *result = 0;
    int status = getaddrinfo(host.c_str(), NULL, NULL, &results);
    if (status == 0) {
        for (result = results; result != NULL; result = result->ai_next) {
            address addr(result->ai_addr, result->ai_addrlen);
            addr.port(port);
            addrs.push_back(addr);
        }
    }
    freeaddrinfo(results);
}

struct backend_connect_error : std::exception {};
struct request_send_error : std::exception {};
struct response_read_error : std::exception {};

class backend_pool : public shared_pool<netsock> {
public:
    backend_pool(proxy_config &conf) :
        shared_pool<netsock>("backend", std::bind(&backend_pool::new_resource, this))
    {
        host2addresses(conf.backend_host, conf.backend_port, backend_addrs);
        if (backend_addrs.empty()) {
            throw errorx("could not resolve backend host: %s", conf.backend_host.c_str());
        }
    }

private:
    std::vector<address> backend_addrs;

    std::shared_ptr<netsock> new_resource() {
        std::shared_ptr<netsock> cs(new netsock(AF_INET, SOCK_STREAM));
        std::vector<address> addrs = backend_addrs;
        std::random_shuffle(addrs.begin(), addrs.end());
        int status = -1;
        for (std::vector<address>::const_iterator i=addrs.begin(); i!=addrs.end(); ++i) {
            status = cs->connect(*i, SEC2MS(10));
            if (status == 0) break;
        }
        if (status != 0) throw backend_connect_error();
        return cs;
    }
};



// globals
static http_response resp_503(503,
    Headers(
    "Connection", "close",
    "Content-Length", "0")
);
static http_response resp_invalid_apikey(400,
    Headers(
    "Warning", "Invalid key",
    "Connection", "close",
    "Content-Length", "0")
);
static http_response resp_expired_apikey(400,
    Headers(
    "Warning", "Expired key",
    "Connection", "close",
    "Content-Length", "0")
);
static http_response resp_out_of_credits(503,
    Headers(
    "Warning", "Credit limit reached",
    "Connection", "close",
    "Content-Length", "0")
);
static proxy_config conf;
static key_engine keng("");
static boost::posix_time::ptime reset_time;

static void calculate_reset_time(
    const boost::posix_time::time_duration &reset_duration,
    boost::posix_time::ptime &reset_time,
    boost::posix_time::time_duration &till_reset)
{
    using namespace boost::gregorian;
    using namespace boost::posix_time;

    ptime now(second_clock::local_time());
    if (reset_time.is_not_a_date_time() || reset_time <= now) {
      ptime reset_start_time(now.date());
      time_iterator tit(reset_start_time, conf.reset_duration);
      while (tit <= now) { ++tit; } // find the next reset time
      reset_time = *tit;
    }
    till_reset = reset_time - now;
}

static void add_rate_limit_headers(http_response &r, uint64_t limit, uint64_t remaining) {
    r.set("X-RateLimit-Limit", limit);
    r.set("X-RateLimit-Remaining", remaining);
    r.set("X-RateLimit-Reset", to_time_t(reset_time));
}

static std::string get_request_apikey(http_server::request &h) {
    uri u = h.get_uri();
    std::string apikey;

    // check http query params for api key
    u.query_part().get("apikey", apikey);
    // also check the http headers for an api key
    if (apikey.empty()) {
        apikey = h.req.get("X-RateLimit-Key");
    }

    return apikey;
}

static void log_request(http_server::request &h) {
    using namespace std::chrono;
    auto elapsed = monotonic_clock::now() - h.start;
    LOG(INFO) << h.agent_ip() << " " <<
        h.req.method << " " <<
        h.req.uri << " " <<
        h.resp.status_code << " " <<
        h.resp.get<size_t>("Content-Length") << " " <<
        duration_cast<milliseconds>(elapsed).count() << " " <<
        get_request_apikey(h);
}

static apikey_state credit_check(http_server::request &h,
    credit_client &cc, apikey &key, uint64_t &value)
{
    using namespace boost::gregorian;
    using namespace boost::posix_time;

    uint64_t ckey = 0;
    std::string db = "ip";
    std::string b32key = get_request_apikey(h);
    inet_pton(AF_INET, h.agent_ip(conf.use_xff).c_str(), &ckey);
    apikey_state state = valid;
    if (b32key.empty()) {
        // use default credit limit for ips
        key.data.credits = conf.credit_limit;
    } else {
        if (!keng.verify(b32key, key)) {
            // report invalid key to caller
            // so we can send an error code back to the client
            // but not before deducting a credit from their ip
            state = invalid;
            if (value == 0) value = 1; // force deducting for invalid keys
            LOG(WARNING) << "invalid apikey: " << b32key << "\n";
        } else {
            LOG(INFO) << "key data: " << key.data << "\n";
            db = "org";
            ckey = key.data.org_id;
            if (key.data.credits == 0) {
                // use default credit limit for keys with no embedded limit
                // XXX: lookup the limit in an external database
                key.data.credits = conf.credit_limit;
            }
            if (key.data.expires != no_expire) {
                ptime now(second_clock::local_time());
                date expire_date(
                    key.data.expires.year,
                    key.data.expires.month,
                    key.data.expires.day);
                if (now.date() > expire_date) {
                    state = expired;
                    if (value == 0) value = 1; // force deducting for invalid keys
                    LOG(WARNING) << "expired apikey: " << b32key << "\n";
                }
            }
        }
    }
    cc.query(db, ckey, value);
    return state;
}

void credit_request(http_server::request &h, credit_client &cc) {
    uint64_t value = 0; // value of 0 will just return how many credits are used
    apikey key;
    switch (credit_check(h, cc, key, value)) {
        case valid:
            break;
        case invalid:
            h.resp = resp_invalid_apikey;
            h.send_response();
            return;
        case expired:
            h.resp = resp_expired_apikey;
            h.send_response();
            return;
    }

    uri u = h.get_uri(conf.vhost);
    json request{
        {"parameters", json({})},
        {"response_type", "json"},
        {"resource", "credit"},
        {"url", u.compose()}
    };

    // this will recalculate the times if needed
    boost::posix_time::time_duration till_reset;
    calculate_reset_time(conf.reset_duration, reset_time, till_reset);

    h.resp = http_response(200);
    add_rate_limit_headers(h.resp, key.data.credits,
        value > key.data.credits ? 0 : (key.data.credits - value));

    json response{
        {"reset", (json_int_t)to_time_t(reset_time)},
        {"limit", (json_int_t)key.data.credits},
        {"remaining", (json_int_t)(value > key.data.credits ? 0 : (key.data.credits - value))},
        {"refresh_in_secs", (json_int_t)(till_reset.total_seconds())}
    };

    json j{
        {"request", request},
        {"response", response}
    };

    h.resp = http_response(200);
    h.resp.set_body(j.dump() + "\n", "application/json");
    h.send_response();
}

void proxy_request(http_server::request &h, credit_client &cc, backend_pool &bp) {
    try {
        apikey key;
        uint64_t value = 1;
        switch (credit_check(h, cc, key, value)) {
            case valid:
                break;
            case invalid:
                goto invalid_apikey_error;
            case expired:
                goto expired_apikey_error;
        }

        if (value > key.data.credits) {
            goto out_of_credits_error;
        }

        backend_pool::scoped_resource cs(bp);
backend_retry:
        try {

            uri u = h.get_uri();
            // clean up query params
            // so the request is more cachable
            uri::query_params params = u.query_part();
            params.erase("apikey");
            // touching the body
            params.erase("callback");
            // jQuery adds _ to prevent caching of JSONP
            params.erase("_");
            u.query = params.str();
            // always request .json, never .js
            // reduce the number of cached paths
            std::string dot_js(".js");
            if (boost::ends_with(u.path, dot_js)) {
                u.path += "on"; // make .js .json
            }
            http_request r(h.req.method, u.compose(true));
            r.headers = h.req.headers;
            // clean up headers that hurt caching
            r.remove("X-Ratelimit-Key");
            if (!conf.vhost.empty()) {
                r.set("Host", conf.vhost);
            }

            std::string data = r.data();
            if (!h.req.body.empty()) {
                data += h.req.body;
            }
            ssize_t nw = cs->send(data.data(), data.size(), SEC2MS(5));
            if (nw <= 0) { throw request_send_error(); }

            http_parser parser;
            h.resp = http_response(&r);
            h.resp.parser_init(&parser);
            buffer buf(4*1024);
            for (;;) {
                buf.reserve(4*1024);
                ssize_t nr = cs->recv(buf.back(), buf.available(), SEC2MS(5));
                if (nr < 0) { throw response_read_error(); }
                buf.commit(nr);
                size_t len = buf.size();
                h.resp.parse(&parser, buf.front(), len);
                buf.remove(len);
                if (h.resp.complete) break;
                if (nr == 0) { throw response_read_error(); }
            }
            boost::posix_time::time_duration till_reset;
            calculate_reset_time(conf.reset_duration, reset_time, till_reset);
            add_rate_limit_headers(h.resp, key.data.credits,
                value > key.data.credits ? 0 : (key.data.credits - value));
            params = h.get_uri().query_part();
            uri::query_params::iterator i = params.find("callback");
            if (i != params.end()) {
                std::string content_type = h.resp.get("Content-Type");
                std::stringstream ss;
                if (content_type.find("json") != std::string::npos) {
                    // wrap response in JSONP
                    ss << i->second << "(" << h.resp.body << ");\n";
                } else {
                    // TODO: would be nice to get some error message text in here
                    ss << i->second << "({\"error\":" << h.resp.status_code << "});\n";
                }
                h.resp.set_body(ss.str(), "application/javascript; charset=utf-8");
                // must return valid javascript or websites that include this JSONP call will break
                h.resp.status_code = 200;
            }
            // HTTP/1.1 requires content-length
            h.resp.set("Content-Length", h.resp.body.size());
            nw = h.send_response();
            if (nw <= 0) { goto response_send_error; }
            return;
        } catch (request_send_error &e) {
            PLOG(ERROR) << "request send error: " << h.req.method << " " << h.req.uri;
            cs.exchange();
            goto backend_retry;
        } catch (response_read_error &e) {
            PLOG(ERROR) << "response read error: " << h.req.method << " " << h.req.uri;
            cs.exchange();
            goto backend_retry;
        }
    } catch (backend_connect_error &e) {
        PLOG(ERROR) << "request connect error " << h.req.method << " " << h.req.uri;
        h.resp = resp_503;
        h.send_response();
        return;
    } catch (std::exception &e) {
        LOG(ERROR) << "exception error: " << h.req.uri << " : " << e.what();
        return;
    }
out_of_credits_error:
    h.resp = resp_out_of_credits;
    h.send_response();
    return;
expired_apikey_error:
    LOG(ERROR) << "expired apikey error " << h.req.method << " " << h.req.uri;
    h.resp = resp_expired_apikey;
    h.send_response();
    return;
invalid_apikey_error:
    LOG(ERROR) << "invalid apikey error " << h.req.method << " " << h.req.uri;
    h.resp = resp_invalid_apikey;
    h.send_response();
    return;
response_send_error:
    PLOG(ERROR) << "response send error: " << h.req.method << " " << h.req.uri;
    return;
}

static void startup() {
    using namespace std::placeholders;
    try {
        backend_pool bp(conf);
        conf.credit_server_port = 9876;
        parse_host_port(conf.credit_server_host, conf.credit_server_port);
        credit_client cc(conf.credit_server_host, conf.credit_server_port);
        http_server proxy(128*1024, SEC2MS(5));
        proxy.set_log_callback(log_request);
        proxy.add_route("/credit.json", std::bind(credit_request, _1, std::ref(cc)));
        proxy.add_route("*", std::bind(proxy_request, _1, std::ref(cc), std::ref(bp)));
        proxy.serve(conf.listen_address, conf.listen_port);
    } catch (std::exception &e) {
        LOG(ERROR) << e.what();
    }
}

int main(int argc, char *argv[]) {
    application app("0.0.1", conf);
    namespace po = boost::program_options;
    app.opts.configuration.add_options()
        ("listen,l", po::value<std::string>(&conf.listen_address)->default_value("0.0.0.0"), "listening address")
        ("port,p", po::value<unsigned short>(&conf.listen_port)->default_value(8080), "listening port")
        ("db", po::value<std::string>(&conf.db), "mysql db name")
        ("db-host", po::value<std::string>(&conf.db_host)->default_value("localhost"), "mysqld host address")
        ("db-user", po::value<std::string>(&conf.db_user)->default_value("ub"), "mysqld user")
        ("credit-server", po::value<std::string>(&conf.credit_server_host)->default_value("localhost"), "credit-server host:port")
        ("credit-limit", po::value<unsigned int>(&conf.credit_limit)->default_value(3600), "credit limit given to new clients")
        ("vhost", po::value<std::string>(&conf.vhost), "use this virtual host address in Host header to backend")
        ("use-xff", po::value<bool>(&conf.use_xff)->default_value(false), "trust and use the ip from X-Forwarded-For when available")
        ("reset-duration", po::value<std::string>(&conf.reset_duration_string)->default_value("1:00:00"), "duration for credit reset interval in hh:mm:ss format")
        ("backend", po::value<std::string>(&conf.backend_host), "backend host:port address")
        ("secret", po::value<std::string>(&conf.secret), "hmac secret key")
    ;
    app.opts.pdesc.add("backend", -1);

    app.parse_args(argc, argv);
    conf.backend_port = 0;
    parse_host_port(conf.backend_host, conf.backend_port);

    if (conf.backend_host.empty() || conf.backend_port == 0) {
        std::cerr << "Error: backend host:port address required\n\n";
        app.showhelp();
        exit(EXIT_FAILURE);
    }

    if (conf.secret.empty()) {
        std::cerr << "Error: secret key is required\n\n";
        app.showhelp();
        exit(EXIT_FAILURE);
    }
    keng.secret = conf.secret;

    using namespace boost::posix_time;
    try {
        conf.reset_duration = duration_from_string(conf.reset_duration_string);
        LOG(INFO) << "Reset duration: " << conf.reset_duration;
    } catch (std::exception &e) {
        LOG(ERROR) << "Bad reset duration: " << conf.reset_duration_string;
        exit(EXIT_FAILURE);
    }

    // large stack needed for getaddrinfo
    taskspawn(startup, 8*1024*1024);
    return app.run();
}

