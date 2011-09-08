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
    uint8_t  key[16];
    uint64_t value;
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

    void send_packet(packet &pkt) {
        pkt.xid = xid++;
        nettask t;
        ssize_t nw = sock.sendto(&pkt, sizeof(pkt), saddr);
        if (nw == sizeof(pkt)) {
            tasks[pkt.xid] = t;
            // TODO: implement tryrecv so timeout works
            if (t.ch.timed_recv(pkt, 100)) {
                VLOG(3) << "channel recv pkt xid: " << pkt.xid << " value: " << pkt.value;
            } else {
                VLOG(3) << "timeout for pkt xid: " << pkt.xid;
            }
        } else {
            abort();
        }
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