#include "ten/app.hh"
#include "ten/net.hh"
#include "credit-client.hh"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>

using namespace ten;

struct credit_server_config : app_config {
    std::string listen_address;
    unsigned short listen_port;
    std::string reset_duration_string;
    boost::posix_time::time_duration reset_duration;
};

// globals
static credit_server_config conf;

class credit_server : boost::noncopyable {
public:
    typedef std::unordered_map<uint64_t, uint64_t> kv_map_t;
    typedef std::unordered_map<std::string, kv_map_t> db_map_t;

    credit_server() : sock{AF_INET, SOCK_DGRAM} {}

    void serve(const std::string &ipaddr, uint16_t port) {
        address baddr{ipaddr.c_str(), port};
        sock.bind(baddr);
        sock.getsockname(baddr);
        LOG(INFO) << "listening on: " << baddr;
        task::spawn([=] {
            reset_task();
        });
        listen_task();
    }

private:
    netsock sock;
    db_map_t dbs;

    boost::posix_time::time_duration till_reset(
        const boost::posix_time::time_duration &reset_duration)
    {
        using namespace boost::gregorian;
        using namespace boost::posix_time;
        ptime now{second_clock::local_time()};
        ptime reset_start_time{now.date()};
        time_iterator tit{reset_start_time, reset_duration};
        while (tit <= now) { ++tit; } // find the next reset time
        ptime reset_time{*tit};
        return reset_time - now;
    }

    void reset_task() {
        using std::chrono::milliseconds;
        for (;;) {
            boost::posix_time::time_duration ttr = till_reset(conf.reset_duration);
            VLOG(3) << "sleeping for " << ttr.total_seconds() << " seconds";
            this_task::sleep_for(milliseconds{ttr.total_milliseconds()});
            VLOG(3) << "reseting credits";
            dbs.clear();
        }
    }

    void listen_task() {
        address faddr;
        packet pkt;
        while (fdwait(sock.s.fd, 'r')) {
            ssize_t nr = sock.s.recvfrom(&pkt, sizeof(pkt), faddr);
            if (nr < (ssize_t)sizeof(pkt)) break;
            VLOG(3) << "got packet xid: " << pkt.xid << " from: " << faddr;
            kv_map_t &db = dbs[pkt.db_name()];
            if (pkt.value == 0) {
                pkt.value = db[pkt.key];
            } else {
                std::pair<kv_map_t::iterator, bool> i = db.insert(std::make_pair((uint64_t)pkt.key, (uint64_t)pkt.value));
                if (!i.second) {
                    // avoid overflow
                    if (pkt.value > (UINT64_MAX - i.first->second)) {
                        pkt.value = UINT64_MAX;
                    } else {
                        pkt.value += i.first->second;
                    }
                    i.first->second = pkt.value;
                }
            }
            VLOG(3) << "db " << pkt.db_name() << " value: " << pkt.value << " for key: " << pkt.key;
            ssize_t nw = sock.s.sendto(&pkt, sizeof(pkt), faddr);
            (void)nw; // ignore send errors
        }
    }
};

void startup() {
    try {
        credit_server server;
        server.serve(conf.listen_address, conf.listen_port);
    } catch (std::exception &e) {
        LOG(ERROR) << "server error: " << e.what();
    }
}

int main(int argc, char *argv[]) {
    return task::main([&] {
        application app{"0.0.1", conf};
        namespace po = boost::program_options;
        app.opts.configuration.add_options()
            ("listen,l", po::value<std::string>(&conf.listen_address)->default_value("0.0.0.0"), "listening address")
            ("port,p", po::value<unsigned short>(&conf.listen_port)->default_value(9876), "listening port")
            ("reset-duration", po::value<std::string>(&conf.reset_duration_string)->default_value("1:00:00"), "duration for credit reset interval in hh:mm:ss format")
            ;

        app.parse_args(argc, argv);
        using namespace boost::posix_time;
        try {
            conf.reset_duration = duration_from_string(conf.reset_duration_string);
            LOG(INFO) << "Reset duration: " << conf.reset_duration;
        } catch (std::exception &e) {
            LOG(ERROR) << "Bad reset duration: " << conf.reset_duration_string;
            exit(1);
        }

        task::spawn(startup);
        app.run();
    });
}
