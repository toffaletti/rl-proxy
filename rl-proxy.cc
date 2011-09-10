#include <netdb.h>

#include "fw/app.hh"
#include "fw/buffer.hh"
#include "fw/http_server.hh"
#include "fw/json.hh"
#include <boost/lexical_cast.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>

#include "keygen.hh"
#include "credit-client.hh"

using namespace fw;

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

// globals
static http_response resp_503(503, "Gateway Timeout", "HTTP/1.1",
    2,
    "Connection", "close",
    "Content-Length", "0"
);
static http_response resp_invalid_apikey(400, "Invalid Key", "HTTP/1.1",
    2,
    "Connection", "close",
    "Content-Length", "0"
);

static proxy_config conf;
static std::vector<address> backend_addrs;
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
      // set the class members to be used by other functions
      reset_time = *tit;
    }
    till_reset = reset_time - now;
}

static void add_rate_limit_headers(http_response &r, uint64_t limit, uint64_t remaining) {
    r.set_header("X-RateLimit-Limit", limit);
    r.set_header("X-RateLimit-Remaining", remaining);
    r.set_header("X-RateLimit-Reset", to_time_t(reset_time));
}

static std::string get_request_apikey(http_server::request &h) {
    uri u = h.get_uri();
    uri::query_params params = u.parse_query();
    uri::query_params::iterator param_it = uri::find_param(params, "apikey");
    std::string apikey;

    // check http query params for api key
    if (param_it != params.end()) {
      // found apikey query param
      apikey = param_it->second;
    }

    // also check the http headers for an api key
    if (apikey.empty()) {
        h.req.header_string("X-RateLimit-Key");
    }

    return apikey;
}

static void log_request(http_server::request &h) {
    boost::posix_time::ptime stop(boost::posix_time::microsec_clock::universal_time());
    boost::posix_time::time_duration elapsed = (stop - h.start);
    LOG(INFO) << h.agent_ip() << " " <<
        h.req.method << " " <<
        h.req.uri << " " <<
        h.resp.status_code << " " <<
        h.resp.header_ull("Content-Length") << " " <<
        elapsed.total_milliseconds() << " " <<
        get_request_apikey(h);
}

static bool credit_check(http_server::request &h, credit_client &cc, apikey &key, uint64_t &value) {
    uint64_t ckey = 0;
    std::string db = "ip";
    std::string b32key = get_request_apikey(h);
    inet_pton(AF_INET, h.agent_ip(conf.use_xff).c_str(), &ckey);
    bool valid = true;
    if (b32key.empty()) {
        // use default credit limit for ips
        key.data.credits = conf.credit_limit;
    } else {
        if (!keng.verify(b32key, key)) {
            // report invalid key to caller
            // so we can send an error code back to the client
            // but not before deducting a credit from their ip
            valid = false;
            LOG(WARNING) << "invalid apikey: " << b32key << "\n";
        } else {
            LOG(INFO) << "key data: " << key.data << "\n";
            db = "org";
            ckey = key.data.org_id;
            if (key.data.credits == 0) {
                // use default credit limit for keys with no embedded limit
                // TODO: lookup the limit in a database?
                key.data.credits = conf.credit_limit;
            }
        }
    }
    cc.query(db, ckey, value);
    return valid;
}

void credit_request(http_server::request &h, credit_client &cc) {
    uint64_t value = 0; // value of 0 will just return how many credits are used
    apikey key;
    if (!credit_check(h, cc, key, value)) {
        h.resp = resp_invalid_apikey;
        h.send_response();
        return;
    }

    json_ptr j = json_ptr(json_object(), json_deleter());
    json_t *request_j = json_object();
    json_object_set_new(request_j, "parameters", json_object());
    json_object_set_new(request_j, "response_type", json_string("json"));
    json_object_set_new(request_j, "resource", json_string("credit"));
    // TODO: make this use the host: header to construct the url
    uri u = h.get_uri(conf.vhost);
    json_object_set_new(request_j, "url", json_string(u.compose().c_str()));
    json_object_set_new(j.get(), "request", request_j);
    json_t *response_j = json_object();

    // this will recalculate the times if needed
    boost::posix_time::time_duration till_reset;
    calculate_reset_time(conf.reset_duration, reset_time, till_reset);

    h.resp = http_response(200, "OK");
    json_object_set_new(response_j, "reset", json_integer(to_time_t(reset_time)));
    json_object_set_new(response_j, "limit", json_integer(key.data.credits));
    json_object_set_new(response_j, "remaining", json_integer(std::max((int64_t)0, (int64_t)(key.data.credits - value))));
    add_rate_limit_headers(h.resp, key.data.credits, std::max((int64_t)0, (int64_t)(key.data.credits - value)));
    json_object_set_new(response_j, "refresh_in_secs", json_integer(till_reset.total_seconds()));
    json_object_set_new(j.get(), "response", response_j);

    boost::shared_ptr<char> js_(json_dumps(j.get(), JSON_COMPACT), free_deleter());
    std::string js(js_.get());
    js += "\n";
    h.resp.set_header("Content-Type", "application/json");
    h.resp.set_header("Content-Length", js.size());

    h.send_response();

    h.sock.send(js.data(), js.size(), SEC2MS(5));
}

void proxy_request(http_server::request &h, credit_client &cc) {
    try {
        // TODO: use persistent connection pool to backend
        task::socket cs(AF_INET, SOCK_STREAM);

        apikey key;
        uint64_t value = 1;
        if (!credit_check(h, cc, key, value)) {
            goto invalid_apikey_error;
        }

        std::vector<address> addrs = backend_addrs;
        std::random_shuffle(addrs.begin(), addrs.end());
        int status = -1;
        for (std::vector<address>::const_iterator i=addrs.begin(); i!=addrs.end(); ++i) {
            status = cs.connect(*i, SEC2MS(10));
            if (status == 0) break;
        }
        if (status != 0) goto request_connect_error;

        uri u = h.get_uri();
        // clean up query params
        // so the request is more cachable
        uri::query_params params = u.parse_query();
        uri::remove_param(params, "apikey");
        // touching the body
        uri::remove_param(params, "callback");
        // jQuery adds _ to prevent caching of JSONP
        uri::remove_param(params, "_");
        u.query = uri::params_to_query(params);
        // always request .json, never .js
        // reduce the number of cached paths
        std::string dot_js(".js");
        if (boost::ends_with(u.path, dot_js)) {
            u.path += "on"; // make .js .json
        }
        http_request r(h.req.method, u.compose(true));
        r.headers = h.req.headers;
        // clean up headers that hurt caching
        r.remove_header("X-Ratelimit-Key");
        if (!conf.vhost.empty()) {
            r.set_header("Host", conf.vhost);
        }

        std::string data = r.data();
        ssize_t nw = cs.send(data.data(), data.size(), SEC2MS(5));
        if (nw <= 0) { goto request_send_error; }
        if (!h.req.body.empty()) {
            nw = cs.send(h.req.body.data(), h.req.body.size(), SEC2MS(5));
            if (nw <= 0) { goto request_send_error; }
        }

        http_parser parser;
        h.resp = http_response(&r);
        h.resp.parser_init(&parser);
        char buf[4096];
        // TODO: need to buffer the entire response to re-add the JSONP wrapper
        for (;;) {
            ssize_t nr = cs.recv(buf, sizeof(buf), SEC2MS(5));
            if (nr < 0) { goto response_read_error; }
            if (h.resp.parse(&parser, buf, nr)) break;
            if (nr == 0) { goto response_read_error; }

        }
        boost::posix_time::time_duration till_reset;
        calculate_reset_time(conf.reset_duration, reset_time, till_reset);
        add_rate_limit_headers(h.resp, key.data.credits, std::max((int64_t)0, (int64_t)(key.data.credits - value)));
        params = h.get_uri().parse_query();
        uri::query_params::iterator i = uri::find_param(params, "callback");
        if (i != params.end()) {
            std::string content_type = h.resp.header_string("Content-Type");
            if (content_type.find("json") != std::string::npos) {
                // wrap response in JSONP
                std::stringstream ss;
                ss << i->second << "(" << h.resp.body << ");\n";
                h.resp.body = ss.str();
            } else {
                // TODO: would be nice to get some error message text in here
                std::stringstream ss;
                ss << i->second << "({\"error\":" << h.resp.status_code << "});\n";
                h.resp.body = ss.str();
            }
            // must return valid javascript or websites that include this JSONP call will break
            h.resp.status_code = 200;
            h.resp.set_header("Content-Type", "application/javascript; charset=utf-8");
        }
        // HTTP/1.1 requires content-length
        h.resp.set_header("Content-Length", h.resp.body.size());
        nw = h.send_response();
        if (nw <= 0) { goto response_send_error; }
        nw = h.sock.send(h.resp.body.data(), h.resp.body.size());
        if (nw <= 0) { goto response_send_error; }
        return;
    } catch (std::exception &e) {
        LOG(ERROR) << "exception error: " << h.req.uri << " : " << e.what();
        return;
    }
invalid_apikey_error:
    PLOG(ERROR) << "invalid apikey error " << h.req.method << " " << h.req.uri;
    h.resp = resp_invalid_apikey;
    h.send_response();
    return;
request_connect_error:
    PLOG(ERROR) << "request connect error " << h.req.method << " " << h.req.uri;
    h.resp = resp_503;
    h.send_response();
    return;
request_send_error:
    PLOG(ERROR) << "request send error: " << h.req.method << " " << h.req.uri;
    h.resp = resp_503;
    h.send_response();
    return;
response_read_error:
    PLOG(ERROR) << "response read error: " << h.req.method << " " << h.req.uri;
    h.resp = resp_503;
    h.send_response();
    return;
response_send_error:
    PLOG(ERROR) << "response send error: " << h.req.method << " " << h.req.uri;
    return;
}

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

int main(int argc, char *argv[]) {
    application app("rl-proxy", "0.0.1", conf);
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
        exit(1);
    }

    if (conf.secret.empty()) {
        std::cerr << "Error: secret key is required\n\n";
        app.showhelp();
        exit(1);
    }
    keng.secret = conf.secret;

    host2addresses(conf.backend_host, conf.backend_port, backend_addrs);
    if (backend_addrs.empty()) {
        LOG(ERROR) << "Could not resolve backend host: " << conf.backend_host;
        exit(1);
    }

    using namespace boost::posix_time;
    try {
        conf.reset_duration = duration_from_string(conf.reset_duration_string);
        LOG(INFO) << "Reset duration: " << conf.reset_duration;
    } catch (std::exception &e) {
        LOG(ERROR) << "Bad reset duration: " << conf.reset_duration_string;
        exit(1);
    }

    conf.credit_server_port = 9876;
    parse_host_port(conf.credit_server_host, conf.credit_server_port);

    credit_client cc(conf.credit_server_host, conf.credit_server_port);

    http_server proxy(128*1024, SEC2MS(5));
    proxy.set_log_callback(log_request);
    proxy.add_callback("/credit.json", boost::bind(credit_request, _1, boost::ref(cc)));
    proxy.add_callback("*", boost::bind(proxy_request, _1, boost::ref(cc)));
    proxy.serve(conf.listen_address, conf.listen_port);
    return app.run();
}

