#include "fw/app.hh"
#include "fw/buffer.hh"
#include "fw/http_server.hh"
#include <boost/lexical_cast.hpp>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>

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
    bool set_host;
    bool use_xff; // ok to trust X-Forwarded-For header
    std::string reset_duration_string;
    boost::posix_time::time_duration reset_duration;
    bool felix;
};

// globals
static http_response resp_503(503, "Gateway Timeout");
static proxy_config conf;


void proxy_request(http_server::request &h) {
    LOG(INFO) << h.req.method << " " << h.req.uri;

    try {
        // TODO: use persistent connection pool to backend
        task::socket cs(AF_INET, SOCK_STREAM);

        if (cs.dial(conf.backend_host.c_str(), conf.backend_port, SEC2MS(10))) {
            goto request_connect_error;
        }

        http_request r(h.req.method, h.req.uri);
        r.headers = h.req.headers;
        std::string data = r.data();
        ssize_t nw = cs.send(data.data(), data.size(), SEC2MS(5));
        if (nw <= 0) { goto request_send_error; }
        if (!h.req.body.empty()) {
            nw = cs.send(h.req.body.data(), h.req.body.size(), SEC2MS(5));
            if (nw <= 0) { goto request_send_error; }
        }

        http_parser parser;
        http_response resp(&r);
        resp.parser_init(&parser);
        bool headers_sent = false;
        char buf[4096];
        for (;;) {
            ssize_t nr = cs.recv(buf, sizeof(buf), SEC2MS(5));
            if (nr < 0) { goto response_read_error; }
            bool complete = resp.parse(&parser, buf, nr);
            if (headers_sent == false && resp.status_code) {
                headers_sent = true;
                nw = h.send_response(resp);
                if (nw <= 0) { goto response_send_error; }
            }

            if (resp.body.size()) {
                if (resp.header_string("Transfer-Encoding") == "chunked") {
                    char lenbuf[64];
                    int len = snprintf(lenbuf, sizeof(lenbuf)-1, "%zx\r\n", resp.body.size());
                    resp.body.insert(0, lenbuf, len);
                    resp.body.append("\r\n");
                }
                nw = h.sock.send(resp.body.data(), resp.body.size());
                if (nw <= 0) { goto response_send_error; }
                resp.body.clear();
            }
            if (complete) {
                // send end chunk
                if (resp.header_string("Transfer-Encoding") == "chunked") {
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
    h.send_response(resp_503);
    return;
request_send_error:
    PLOG(ERROR) << "request send error: " << h.req.method << " " << h.req.uri;
    h.send_response(resp_503);
    return;
response_read_error:
    PLOG(ERROR) << "response read error: " << h.req.method << " " << h.req.uri;
    h.send_response(resp_503);
    return;
response_send_error:
    PLOG(ERROR) << "response send error: " << h.req.method << " " << h.req.uri;
    return;
}

int main(int argc, char *argv[]) {
    application app("rl-proxy", "0.0.1", conf);
    namespace po = boost::program_options;
    app.opts.configuration.add_options()
        ("listen,l", po::value<std::string>(&conf.listen_address)->default_value("0.0.0.0"), "listening address")
        ("port,p", po::value<unsigned short>(&conf.listen_port)->default_value(8080), "listening port")
        ("db", po::value<std::string>(&conf.db)->default_value(""), "mysql db name")
        ("db-host", po::value<std::string>(&conf.db_host)->default_value("localhost"), "mysqld host address")
        ("db-user", po::value<std::string>(&conf.db_user)->default_value("ub"), "mysqld user")
        ("credit-server", po::value<std::string>(&conf.credit_server_addr)->default_value("localhost"), "credit-server address")
        ("credit-limit", po::value<unsigned int>(&conf.credit_limit)->default_value(10000), "credit limit given to new clients")
        ("vhost", po::value<std::string>(&conf.vhost)->default_value("localhost"), "virtual host address")
        ("set-host", po::value<bool>(&conf.set_host)->default_value(false), "modify the Host http header to be the backend host address")
        ("use-xff", po::value<bool>(&conf.use_xff)->default_value(false), "trust and use the ip from X-Forwarded-For when available")
        ("reset-duration", po::value<std::string>(&conf.reset_duration_string)->default_value("1:00:00"), "duration for credit reset interval in hh:mm:ss format")
        ("backend", po::value<std::string>(&conf.backend_host), "backend host:port address")
    ;
    app.opts.pdesc.add("backend", -1);

    app.parse_args(argc, argv);
    parse_host_port(conf.backend_host, conf.backend_port);
    http_server proxy(4*1024*1024, SEC2MS(5)); // 4mb stack size, 5 second timeout
    proxy.add_callback("*", proxy_request);
    proxy.serve(conf.listen_address, conf.listen_port);
    return app.run();
}
