#include <netdb.h>

#include "fw/app.hh"
#include "fw/buffer.hh"
#include "fw/http_server.hh"
#include "fw/json.hh"
#include <boost/lexical_cast.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>

#include "keygen.hh"

using namespace fw;

struct proxy_config : app_config {
    std::string backend_host;
    unsigned short backend_port;
    std::string db;
    std::string db_host;
    std::string db_user;
    std::string credit_server_addr;
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
static http_response resp_503(503, "Gateway Timeout");
static proxy_config conf;
static std::vector<address> backend_addrs;
static key_engine keng("");

static void add_rate_limit_headers(http_response &r, uint64_t credits_remaining) {
    //r.set_header("X-RateLimit-Limit", credit_limit(request));
    r.set_header("X-RateLimit-Remaining", credits_remaining);
    //r.set_header("X-RateLimit-Reset", reset_time_t);
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

void credit_request(http_server::request &h) {
    uint64_t value = 0;
    VLOG(3) << "got credit value: " << value;
    unsigned int limit = 0;
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
    //calculate_reset_time();

    h.resp = http_response(200, "OK");
    //json_object_set_new(response_j, "reset", json_integer(reset_time_t));
    json_object_set_new(response_j, "limit", json_integer(limit));
    if (value <= limit) {
      json_object_set_new(response_j, "remaining", json_integer(limit - value));
      add_rate_limit_headers(h.resp, limit-value);
    } else {
      json_object_set_new(response_j, "remaining", json_integer(0));
      add_rate_limit_headers(h.resp, 0);
    }
    //json_object_set_new(response_j, "refresh_in_secs", json_integer(till_reset.total_seconds()));
    json_object_set_new(j.get(), "response", response_j);

    boost::shared_ptr<char> js_(json_dumps(j.get(), JSON_COMPACT), free_deleter());
    std::string js(js_.get());
    js += "\n";
    h.resp.set_header("Content-Type", "application/json");
    h.resp.set_header("Content-Length", js.size());

    h.send_response();

    h.sock.send(js.data(), js.size(), SEC2MS(5));
}

void proxy_request(http_server::request &h) {
    try {
        // TODO: use persistent connection pool to backend
        task::socket cs(AF_INET, SOCK_STREAM);

        std::string apikey = get_request_apikey(h);
        if (!keng.verify(apikey)) {
            LOG(WARNING) << "invalid apikey: " << apikey << "\n";
        }

        std::vector<address> addrs = backend_addrs;
        std::random_shuffle(addrs.begin(), addrs.end());
        int status = -1;
        for (std::vector<address>::const_iterator i=addrs.begin(); i!=addrs.end(); ++i) {
            status = cs.connect(*i, SEC2MS(10));
            if (status == 0) break;
        }
        if (status != 0) goto request_connect_error;

        http_request r(h.req.method, h.req.uri);
        r.headers = h.req.headers;
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
        bool headers_sent = false;
        char buf[4096];
        for (;;) {
            ssize_t nr = cs.recv(buf, sizeof(buf), SEC2MS(5));
            if (nr < 0) { goto response_read_error; }
            bool complete = h.resp.parse(&parser, buf, nr);
            if (headers_sent == false && h.resp.status_code) {
                headers_sent = true;
                add_rate_limit_headers(h.resp, 0);
                nw = h.send_response();
                if (nw <= 0) { goto response_send_error; }
            }

            if (h.resp.body.size()) {
                if (h.resp.header_string("Transfer-Encoding") == "chunked") {
                    char lenbuf[64];
                    int len = snprintf(lenbuf, sizeof(lenbuf)-1, "%zx\r\n", h.resp.body.size());
                    h.resp.body.insert(0, lenbuf, len);
                    h.resp.body.append("\r\n");
                }
                nw = h.sock.send(h.resp.body.data(), h.resp.body.size());
                if (nw <= 0) { goto response_send_error; }
                h.resp.body.clear();
            }
            if (complete) {
                // send end chunk
                if (h.resp.header_string("Transfer-Encoding") == "chunked") {
                    nw = h.sock.send("0\r\n\r\n", 5);
                }
                break;
            }
            if (nr == 0) { goto response_read_error; }
        }
        return;
    } catch (std::exception &e) {
        LOG(ERROR) << "exception error: " << h.req.uri << " : " << e.what();
        return;
    }
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
        ("credit-server", po::value<std::string>(&conf.credit_server_addr)->default_value("localhost"), "credit-server address")
        ("credit-limit", po::value<unsigned int>(&conf.credit_limit)->default_value(10000), "credit limit given to new clients")
        ("vhost", po::value<std::string>(&conf.vhost), "use this virtual host address in Host header to backend")
        ("use-xff", po::value<bool>(&conf.use_xff)->default_value(false), "trust and use the ip from X-Forwarded-For when available")
        ("reset-duration", po::value<std::string>(&conf.reset_duration_string)->default_value("1:00:00"), "duration for credit reset interval in hh:mm:ss format")
        ("backend", po::value<std::string>(&conf.backend_host), "backend host:port address")
        ("secret", po::value<std::string>(&conf.secret), "hmac secret key")
    ;
    app.opts.pdesc.add("backend", -1);

    app.parse_args(argc, argv);
    parse_host_port(conf.backend_host, conf.backend_port);

    if (conf.backend_host.empty()) {
        std::cerr << "Error: backend host address required\n\n";
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

    resp_503.append_header("Connection", "close");
    resp_503.append_header("Content-Length", "0");

    http_server proxy(128*1024, SEC2MS(5));
    proxy.set_log_callback(log_request);
    proxy.add_callback("/credit.json", credit_request);
    proxy.add_callback("*", proxy_request);
    proxy.serve(conf.listen_address, conf.listen_port);
    return app.run();
}

