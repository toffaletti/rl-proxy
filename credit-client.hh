#include "fw/descriptors.hh"
#include "fw/task.hh"
#include "fw/channel.hh"
#include "fw/logging.hh"
#include <netdb.h>
#include <boost/unordered_map.hpp>
#include <boost/bind.hpp>

using namespace fw;

struct packet {
    uint64_t xid;
    char db[8];
    uint64_t key;
    uint64_t value;

    std::string db_name() { return std::string(db, strnlen(db, sizeof(db))); }
    void set_db(const std::string &db_) {
        if (db_.size() > sizeof(db)) { throw errorx("db name %s too long", db_.c_str()); }
        memcpy(db, db_.data(), db_.size());
        if (db_.size() < sizeof(db)) {
            db[db_.size()] = 0;
        }
    }
} __attribute__((packed));

class credit_client : boost::noncopyable {
public:
    struct nettask {
        channel<packet> ch;
    };
    typedef boost::unordered_map<uint64_t, nettask> task_map;

    credit_client(
        const std::string &host_port,
        uint16_t port = 9876)
        : sock(AF_INET, SOCK_DGRAM), xid(0)
    {
        std::string host(host_port);
        parse_host_port(host, port);

        saddr.addr.sa_in.sin_family = AF_INET;
        {
            struct addrinfo hint;
            memset(&hint, 0, sizeof(hint));
            hint.ai_family = AF_INET;
            struct addrinfo *result, *rp;
            int s = getaddrinfo(host.c_str(), NULL, &hint, &result);
            if (s != 0) {
                throw std::runtime_error("invalid address for credit_client: " + host + " " + gai_strerror(s));
            }
            for (rp = result; rp != NULL; rp = rp->ai_next) {
                // just use the first address
                memcpy(&saddr, rp->ai_addr, rp->ai_addrlen);
                break;
            }
            freeaddrinfo(result);
        }
        saddr.port(port);

        address baddr;
        baddr.family(saddr.family());
        sock.bind(baddr);
        _recv_task = task::spawn(boost::bind(&credit_client::recv_task, this));
    }

    bool query(const std::string &db, uint64_t key, uint64_t &val, unsigned int timeout_ms=100) {
        packet pkt;
        pkt.xid = xid++;
        pkt.set_db(db);
        pkt.key = key;
        pkt.value = val;
        nettask t;
        ssize_t nw = sock.sendto(&pkt, sizeof(pkt), saddr);
        if (nw == sizeof(pkt)) {
            tasks[pkt.xid] = t;
            bool success = t.ch.timed_recv(pkt, timeout_ms);
            if (success) { val = pkt.value; }
            return success;
        }
        return false;
    }

    void close() {
        _recv_task.cancel();
    }
private:
    socket_fd sock;
    address saddr;
    uint64_t xid;
    task_map tasks;
    task _recv_task;

    void recv_task() {
        address faddr;
        packet pkt;
        while (task::poll(sock.fd, EPOLLIN)) {
            ssize_t nr = sock.recvfrom(&pkt, sizeof(pkt), faddr);
            if (nr < (ssize_t)sizeof(pkt)) break;
            VLOG(3) << "got packet xid: " << pkt.xid;
            task_map::iterator it = tasks.find(pkt.xid);
            if (it != tasks.end()) {
                it->second.ch.send(pkt);
                tasks.erase(it);
            }
        }
    }
};