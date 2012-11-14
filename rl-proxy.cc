#include <netdb.h>
#include <memory>
#include <unordered_map>

#include "ten/app.hh"
#include "ten/buffer.hh"
#include "ten/http/server.hh"
#include "ten/json.hh"
#include "ten/shared_pool.hh"
#include <boost/lexical_cast.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/regex.hpp> // libstdc++-4.7 regex isn't ready yet

#include "keygen.hh"
#include "credit-client.hh"

using namespace ten;
const size_t default_stacksize=256*1024;

struct proxy_config : app_config {
    std::string backend_host;
    unsigned short backend_port;
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
    bool secure_log;
    std::string grandfather_file;
};

static void host2addresses(std::string &host, uint16_t port, std::vector<address> &addrs) {
    struct addrinfo *results = 0;
    struct addrinfo *result = 0;
    int status = getaddrinfo(host.c_str(), NULL, NULL, &results);
    if (status == 0) {
        for (result = results; result != NULL; result = result->ai_next) {
            address addr{result->ai_addr, result->ai_addrlen};
            addr.port(port);
            addrs.push_back(addr);
        }
    }
    freeaddrinfo(results);
}

// TODO: maybe<> and maybe_if<> would work well here once chip has time
static std::pair<bool, std::string> get_jsonp(http_exchange &ex) {
    auto params = ex.get_uri().query_part();
    auto i = params.find("callback");
    if (i == params.end()) {
        return std::make_pair(false, std::string());
    }
    return std::make_pair(true, i->second);
}

static void make_jsonp_response(http_exchange &ex, const std::string &callback) {
    std::string content_type = ex.resp.get("Content-Type");
    std::stringstream ss;
    if (content_type.find("json") != std::string::npos) {
        // wrap response in JSONP
        ss << callback << "(" << ex.resp.body << ");\n";
    } else {
        std::string msg = ex.resp.get("Warning");
        if (msg.empty()) {
            msg = ex.resp.reason();
        }
        json status{
            {"status", static_cast<json_int_t>(ex.resp.status_code)},
            {"reason", msg}
        };
        ss << callback << "(" << status << ");\n";
    }
    ex.resp.set_body(ss.str(), "application/javascript; charset=utf-8");
    // must return valid javascript or websites that include this JSONP call will break
    ex.resp.status_code = 200;
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
        std::shared_ptr<netsock> cs{new netsock(AF_INET, SOCK_STREAM)};
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
static http_response resp_connect_error_503{503,
    http_headers(
    "Connection", "close",
    "Content-Length", "0")
};
static http_response resp_invalid_apikey{400,
    http_headers(
    "Warning", "Invalid key",
    "Connection", "close",
    "Content-Length", "0")
};
static http_response resp_expired_apikey{400,
    http_headers(
    "Warning", "Expired key",
    "Connection", "close",
    "Content-Length", "0")
};
static http_response resp_out_of_credits{503,
    http_headers(
    "Warning", "Credit limit reached",
    "Connection", "close",
    "Content-Length", "0")
};
static proxy_config conf;
static key_engine keng{""};
static boost::posix_time::ptime reset_time;
static std::unordered_map<std::string, uint64_t> grandfather_keys;

class log_request_t {
    http_exchange &_ex;
    explicit log_request_t(http_exchange &ex) : _ex(ex) {}
public:
    friend std::ostream &operator << (std::ostream &o, const log_request_t &lr);
    friend log_request_t log_r(http_exchange &ex);
};

log_request_t log_r(http_exchange &ex) {
    return log_request_t(ex);
}

std::ostream &operator << (std::ostream &o, const log_request_t &lr) {
    if (conf.secure_log) {
        o << lr._ex.req.method << " " << lr._ex.get_uri().path;
    } else {
        o << lr._ex.req.method << " " << lr._ex.req.uri;
    }
    return o;
}

static void calculate_reset_time(
    const boost::posix_time::time_duration &reset_duration,
    boost::posix_time::ptime &reset_time,
    boost::posix_time::time_duration &till_reset)
{
    using namespace boost::gregorian;
    using namespace boost::posix_time;

    ptime now{second_clock::local_time()};
    if (reset_time.is_not_a_date_time() || reset_time <= now) {
      ptime reset_start_time{now.date()};
      time_iterator tit{reset_start_time, conf.reset_duration};
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

static std::string get_request_apikey(http_exchange &ex) {
    uri u = ex.get_uri();
    std::string apikey;

    // check http query params for api key
    u.query_part().get("apikey", apikey);
    // also check the http headers for an api key
    if (apikey.empty()) {
        apikey = ex.req.get("X-RateLimit-Key");
    }

    return apikey;
}

static void log_request(http_exchange &ex) {
    using namespace std::chrono;
    auto elapsed = steady_clock::now() - ex.start;
    if (conf.secure_log) {
        LOG(INFO) <<
            ex.req.method << " " <<
            ex.get_uri().path << " " <<
            ex.resp.status_code << " " <<
            ex.resp.get<size_t>("Content-Length") << " " <<
            duration_cast<milliseconds>(elapsed).count() << " " <<
            get_request_apikey(ex);
    } else {
        LOG(INFO) <<
            ex.agent_ip() << " " <<
            ex.req.method << " " <<
            ex.req.uri << " " <<
            ex.resp.status_code << " " <<
            ex.resp.get<size_t>("Content-Length") << " " <<
            duration_cast<milliseconds>(elapsed).count() << " " <<
            get_request_apikey(ex);
    }
}

static apikey_state credit_check(http_exchange &ex,
    credit_client &cc, apikey &key, uint64_t &value)
{
    using namespace boost::gregorian;
    using namespace boost::posix_time;

    uint64_t ckey = 0;
    std::string db = "ip";
    std::string rawkey = get_request_apikey(ex);
    inet_pton(AF_INET, ex.agent_ip(conf.use_xff).c_str(), &ckey);
    apikey_state state = valid;
    if (rawkey.empty()) {
        // use default credit limit for ips
        key.data.credits = conf.credit_limit;
    } else {
        // check grandfathered keys
        auto it = grandfather_keys.find(rawkey);
        if (it != grandfather_keys.end()) {
            db = "old";
            value = 1;
            std::hash<std::string> h;
            ckey = h(rawkey);
            key.data.credits = it->second;
        } else if (!keng.verify(rawkey, key)) {
            // report invalid key to caller
            // so we can send an error code back to the client
            // but not before deducting a credit from their ip
            state = invalid;
            if (value == 0) value = 1; // force deducting for invalid keys
            LOG(WARNING) << "invalid apikey: |" << rawkey << "|\n";
        } else {
            LOG(INFO) << "apikey: " << rawkey << " data: " << key.data << "\n";
            // TODO: org only db
            db = "app";
            uint64_t org_id = key.data.org_id;
            uint64_t app_id = key.data.app_id;

            // pack org_id and app_id into 64 bits for the key
            ckey = org_id << 16;
            ckey |= app_id;

            if (key.data.credits == 0) {
                // use default credit limit for keys with no embedded limit
                // XXX: lookup the limit in an external database
                key.data.credits = conf.credit_limit;
            }
            if (key.data.expires != 0) {
                if (time(0) >= (time_t)key.data.expires) {
                    state = expired;
                    if (value == 0) value = 1; // force deducting for invalid keys
                    LOG(WARNING) << "expired apikey: " << rawkey << "\n";
                }
            }
        }
    }
    cc.query(db, ckey, value);
    return state;
}

static void credit_request(http_exchange &ex, credit_client &cc) {
    uint64_t value = 0; // value of 0 will just return how many credits are used
    apikey key = {};
    switch (credit_check(ex, cc, key, value)) {
        case valid:
            break;
        case invalid:
            ex.resp = resp_invalid_apikey;
            ex.send_response();
            return;
        case expired:
            ex.resp = resp_expired_apikey;
            ex.send_response();
            return;
    }

    uri u = ex.get_uri(conf.vhost);
    json request{
        {"parameters", json{{}}},
        {"response_type", "json"},
        {"resource", "credit"},
        {"url", u.compose()}
    };

    // this will recalculate the times if needed
    boost::posix_time::time_duration till_reset;
    calculate_reset_time(conf.reset_duration, reset_time, till_reset);

    ex.resp = http_response{200};
    add_rate_limit_headers(ex.resp, key.data.credits,
        value > key.data.credits ? 0 : key.data.credits);

    json_int_t credit_limit = key.data.credits;
    json_int_t credits_remaining = 
        (value > key.data.credits ? 0 : key.data.credits);
    json response{
        {"reset", to_time_t(reset_time)},
        {"limit", credit_limit},
        {"remaining", credits_remaining},
        {"refresh_in_secs", till_reset.total_seconds()}
    };

    json j{
        {"request", request},
        {"response", response}
    };

    ex.resp.set_body(j.dump() + "\n", "application/json");
    auto jp = get_jsonp(ex);
    if (jp.first) {
        make_jsonp_response(ex, jp.second);
    }
    ex.send_response();
}

static http_request normalize_request(http_exchange &ex) {
    uri u = ex.get_uri();
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
    std::string dot_js{".js"};
    if (boost::ends_with(u.path, dot_js)) {
        u.path += "on"; // make .js .json
    }
    http_request r(ex.req.method, u.compose(true));
    r.headers = ex.req.headers;
    // clean up headers that hurt caching
    r.remove("X-Ratelimit-Key");
    if (!conf.vhost.empty()) {
        r.set("Host", conf.vhost);
    }

    return r;
}

static void perform_proxy(http_exchange &ex, credit_client &cc, backend_pool &bp) {
    apikey key = {};
    uint64_t value = 1;
    switch (credit_check(ex, cc, key, value)) {
        case valid:
            break;
        case invalid:
            LOG(ERROR) << "invalid apikey error " << log_r(ex);
            ex.resp = resp_invalid_apikey;
            return;
        case expired:
            LOG(ERROR) << "expired apikey error " << log_r(ex);
            ex.resp = resp_expired_apikey;
            return;
    }

    if (value > key.data.credits) {
        ex.resp = resp_out_of_credits;
        return;
    }

    for (;;) {
        backend_pool::scoped_resource cs{bp};
        try {
            http_request r = normalize_request(ex);

            std::string data = r.data();
            if (!ex.req.body.empty()) {
                data += ex.req.body;
            }
            ssize_t nw = cs->send(data.data(), data.size(), SEC2MS(5));
            if (nw <= 0) { throw request_send_error(); }

            http_parser parser;
            ex.resp = http_response{&r};
            ex.resp.parser_init(&parser);
            buffer buf(4*1024);
            for (;;) {
                buf.reserve(4*1024);
                ssize_t nr = cs->recv(buf.back(), buf.available(), SEC2MS(5));
                if (nr < 0) { throw response_read_error(); }
                buf.commit(nr);
                size_t len = buf.size();
                ex.resp.parse(&parser, buf.front(), len);
                buf.remove(len);
                if (ex.resp.complete) break;
                if (nr == 0) { throw response_read_error(); }
            }

            // TODO: this would be a useful general function on http_request
            if ((ex.resp.version == http_1_0 && boost::iequals(ex.resp.get("Connection"), "Keep-Alive")) ||
                    !boost::iequals(ex.resp.get("Connection"), "close"))
            {
                // try to keep connection persistent by returning it to the pool
                cs.done();
            }

            boost::posix_time::time_duration till_reset;
            calculate_reset_time(conf.reset_duration, reset_time, till_reset);
            add_rate_limit_headers(ex.resp, key.data.credits,
                value > key.data.credits ? 0 : (key.data.credits - value));
            return;
        } catch (request_send_error &e) {
            PLOG(ERROR) << "request send error: " << log_r(ex);
            continue;
        } catch (response_read_error &e) {
            PLOG(ERROR) << "response read error: " << log_r(ex);
            continue;
        }
    }
}

static void proxy_request(http_exchange &ex, credit_client &cc, backend_pool &bp) {
    try {
        perform_proxy(ex, cc, bp);
        auto jp = get_jsonp(ex);
        if (jp.first) { // is this jsonp?
            make_jsonp_response(ex, jp.second);
        }
        // HTTP/1.1 requires content-length
        ex.resp.set("Content-Length", ex.resp.body.size());
        ssize_t nw = ex.send_response();
        if (nw <= 0) {
            PLOG(ERROR) << "response send error: " << log_r(ex);
        }
    } catch (backend_connect_error &e) {
        PLOG(ERROR) << "request connect error " << log_r(ex);
        ex.resp = resp_connect_error_503;
        ex.send_response();
    } catch (std::exception &e) {
        LOG(ERROR) << "exception error: " << log_r(ex) << " : " << e.what();
    }
}

static void startup() {
    using namespace std::placeholders;
    try {
        backend_pool bp{conf};
        conf.credit_server_port = 9876;
        parse_host_port(conf.credit_server_host, conf.credit_server_port);
        credit_client cc(conf.credit_server_host, conf.credit_server_port);
        std::shared_ptr<http_server> proxy = std::make_shared<http_server>(128*1024, SEC2MS(5));
        proxy->set_log_callback(log_request);
        proxy->add_route("/credit.json", std::bind(credit_request, _1, std::ref(cc)));
        proxy->add_route("*", std::bind(proxy_request, _1, std::ref(cc), std::ref(bp)));
        proxy->serve(conf.listen_address, conf.listen_port);
    } catch (std::exception &e) {
        LOG(ERROR) << e.what();
    }
}

int main(int argc, char *argv[]) {
    application app{SCM_VERSION, conf};
    namespace po = boost::program_options;
    app.opts.configuration.add_options()
        ("listen,l", po::value<std::string>(&conf.listen_address)->default_value("0.0.0.0"), "listening address")
        ("port,p", po::value<unsigned short>(&conf.listen_port)->default_value(8080), "listening port")
        ("credit-server", po::value<std::string>(&conf.credit_server_host)->default_value("localhost"),
         "credit-server host:port")
        ("credit-limit", po::value<unsigned int>(&conf.credit_limit)->default_value(3600),
         "credit limit given to new clients")
        ("vhost", po::value<std::string>(&conf.vhost), "use this virtual host address in Host header to backend")
        ("use-xff", po::value<bool>(&conf.use_xff)->default_value(false),
         "trust and use the ip from X-Forwarded-For when available")
        ("reset-duration", po::value<std::string>(&conf.reset_duration_string)->default_value("1:00:00"),
         "duration for credit reset interval in hh:mm:ss format")
        ("backend", po::value<std::string>(&conf.backend_host), "backend host:port address")
        ("secret", po::value<std::string>(&conf.secret), "hmac secret key")
        ("secure-log", po::value<bool>(&conf.secure_log)->default_value(false), "secure logging format")
        ("grandfather", po::value<std::string>(&conf.grandfather_file), "grandfathered keys file")
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

    if (!conf.grandfather_file.empty()) {
        // TODO: use std::regex once libstdc++ has fully implemented it
        using namespace boost;
        regex key_line_re(
                "^[a-zA-Z0-9]+$");
        regex key_limit_line_re(
                "^([a-zA-Z0-9]+)[\\ \\t]+([0-9]+)$");

        std::ifstream gf(conf.grandfather_file);
        if (gf.is_open()) {
            std::string line;
            while (std::getline(gf, line)) {
                if (line.empty() || line[0] == '#') continue;
                match_results<std::string::const_iterator> result;
                if (regex_match(line, key_line_re)) {
                    VLOG(2) << "adding grandfather key: " << line;
                    // unlimited
                    grandfather_keys.insert(std::make_pair(line, (~0)));
                } else if (regex_match(line, result, key_limit_line_re)) {
                    uint64_t limit = boost::lexical_cast<uint64_t>(result[2]);
                    VLOG(2) << "adding grandfather key: " << result[1] << " " << limit;
                    grandfather_keys.insert(std::make_pair(result[1], limit));
                } else {
                    LOG(ERROR) << "skipping invalid line: " << line;
                }
            }
        } else {
            LOG(ERROR) << "Could not open " << conf.grandfather_file;
            exit(EXIT_FAILURE);
        }
    }

    // large stack needed for getaddrinfo
    taskspawn(startup, 8*1024*1024);
    return app.run();
}

