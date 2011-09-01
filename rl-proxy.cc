#include "fw/runner.hh"
#include "fw/task.hh"
#include "fw/buffer.hh"
#include "fw/http/http_message.hh"
#include "fw/uri/uri.hh"
#include "fw/logging.hh"
#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <fnmatch.h>

using namespace fw;

#define SEC2MS(s) (s*1000)

std::string backend_host = "web619";
uint16_t backend_port = 6006;

static http_response resp_503(503, "Gateway Timeout");

class httpd : boost::noncopyable {
public:
    struct request {
        request(http_request &req_, task::socket &sock_)
            : req(req_), sock(sock_), resp_sent(false) {}

        //! compose a uri from the request uri
        uri get_uri() {
            std::string host = req.header_string("Host");
            if (boost::starts_with(req.uri, "http://")) {
                return req.uri;
            }

            if (host.empty()) {
                // just make up a host
                host = "localhost";
            }
            uri tmp;
            tmp.host = host;
            tmp.scheme = "http";
            tmp.path = req.uri.c_str();
            return tmp.compose();
        }

        //! send response to this request
        ssize_t send_response(const http_response &resp) {
            if (resp_sent) return 0;
            resp_sent = true;
            std::string data = resp.data();
            ssize_t nw = sock.send(data.data(), data.size());
            // TODO: send body?
            return nw;
        }

        //! the ip of the host making the request
        //! might use the X-Forwarded-For header
        std::string request_ip(bool use_xff=false) const {
            if (use_xff) {
                std::string xffs = req.header_string("X-Forwarded-For");
                const char *xff = xffs.c_str();
                if (xff) {
                    // pick the first addr    
                    int i;
                    for (i=0; *xff && i<256 && !isdigit((unsigned char)*xff); i++, xff++) {}
                    if (*xff && i < 256) {
                        // now, find the end 
                        const char *e = xff;
                        for (i = 0; *e && i<256 && (isdigit((unsigned char)*e) || *e == '.'); i++, e++) {}
                        if (i < 256 && e >= xff + 7 ) {
                            return std::string(xff, e - xff);
                        }
                    }
                }
            }
            address addr;
            if (sock.getpeername(addr)) {
                char buf[INET6_ADDRSTRLEN];
                return addr.ntop(buf, sizeof(buf));
            }
            return "";
        }

        ~request() {
            // ensure a response is sent
            send_response(http_response(404, "Not Found"));
        }

        http_request &req;
        task::socket &sock;
        bool resp_sent;
    };

    typedef boost::function<void (request &)> func_type;
    typedef boost::tuple<std::string, func_type> tuple_type;
    typedef std::vector<tuple_type> map_type;

    httpd() : sock(AF_INET, SOCK_STREAM) {
        sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1);
    }

    void add_callback(const std::string &pattern, const func_type &f) {
      _map.push_back(tuple_type(pattern, f));
    }

    void serve(const std::string &ipaddr, uint16_t port) {
        address baddr(ipaddr.c_str(), port);
        sock.bind(baddr);
        sock.getsockname(baddr);
        LOG(INFO) << "listening on: " << baddr;
        task::spawn(boost::bind(&httpd::listen_task, this));
    }

private:
    task::socket sock;
    map_type _map;

    void listen_task() {
        sock.listen();

        for (;;) {
            address client_addr;
            int fd;
            while ((fd = sock.accept(client_addr, 0)) > 0) {
                task::spawn(boost::bind(&httpd::client_task, this, fd), 0, 4*1024*1024);
            }
        }
    }

    void client_task(int fd) {
        task::socket s(fd);
        buffer buf(4*1024);
        http_parser parser;

        buffer::slice rb = buf(0);
        for (;;) {
            http_request req;
            req.parser_init(&parser);
            for (;;) {
                ssize_t nr = s.recv(rb.data(), rb.size(), SEC2MS(5));
                if (nr < 0) return;
                if (req.parse(&parser, rb.data(), nr)) break;
                if (nr == 0) return;
            }
            // handle request
            handle_request(req, s);
        }
    }

    void handle_request(http_request &req, task::socket &s) {
        request r(req, s);
        // not super efficient, but good enough
        for (map_type::const_iterator i= _map.begin(); i!= _map.end(); i++) {
            DVLOG(5) << "matching pattern: " << i->get<0>();
            if (fnmatch(i->get<0>().c_str(), req.uri.c_str(), 0) == 0) {
                i->get<1>()(r);
                return;
            }
        }
    }
};

void proxy_request(httpd::request &h) {
    LOG(INFO) << h.req.method << " " << h.req.uri;

    try {
        // TODO: use persistent connection pool to backend
        task::socket cs(AF_INET, SOCK_STREAM);

        if (cs.dial(backend_host.c_str(), backend_port, SEC2MS(10))) {
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
    runner::init();
    httpd proxy;
    proxy.add_callback("*", proxy_request);
    proxy.serve("0.0.0.0", 8080);
    return runner::main();
}
