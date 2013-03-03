#include "ten/descriptors.hh"
#include "ten/task.hh"
#include "ten/channel.hh"
#include "ten/logging.hh"
#include <netdb.h>
#include <unordered_map>
#include <unordered_set>
#include <boost/utility.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/regex.hpp> // libstdc++-4.7 regex isn't ready yet
#include <boost/lexical_cast.hpp>
#include <fstream>
#include "keygen.hh"

using namespace ten;
using namespace std::chrono;

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
    typedef std::unordered_map<uint64_t, nettask> task_map;

    credit_client(
        const std::string &host_port,
        uint16_t port = 9876,
        optional<std::string> blacklist_file = nullopt,
        optional<std::string> grandfather_file = nullopt)
        : sock(AF_INET, SOCK_DGRAM), xid(0)
    {
        std::string host(host_port);
        parse_host_port(host, port);

        if (blacklist_file) {
            _blacklist_keys = read_blacklist_file(*blacklist_file);
        }

        if (grandfather_file) {
            _grandfather_keys = read_grandfather_file(*grandfather_file);
        }

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

        address baddr(saddr.family());
        sock.bind(baddr);
        _recv_tid = taskspawn(std::bind(&credit_client::recv_task, this));
    }

    ~credit_client() {
        close();
    }

    apikey_state full_query(optional<std::string> optional_ip,
            std::string rawkey,
            uint64_t &ckey,
            apikey &key,
            std::string &db,
            uint64_t &value,
            key_engine &keng,
            unsigned credit_limit
            )
    {
        ckey = 0;
        db = "ip";
        std::string ip = get_value_or(optional_ip, "");
        if (inet_pton(AF_INET, ip.c_str(), &ckey) != 1) {
            LOG(WARNING) << "invalid ip used in credit check: " << ip;
        }
        apikey_state state = valid;
        if (rawkey.empty()) {
            // use default credit limit for ips
            key.data.credits = credit_limit;
        } else {
            // check blacklisted keys
            if (_blacklist_keys.count(rawkey)) {
                return blacklist;
            }
            // check grandfathered keys
            auto it = _grandfather_keys.find(rawkey);
            if (it != _grandfather_keys.end()) {
                db = "old";
                if (it->second == (uint64_t)~0) {
                    value = 0; // never increment credits for unlimited keys
                }
                std::hash<std::string> h;
                ckey = h(rawkey);
                key.data.credits = it->second;
            } else if (!keng.verify(rawkey, key)) {
                // report invalid key to caller
                // so we can send an error code back to the client
                // but not before deducting a credit from their ip
                state = invalid;
                if (value == 0) value = 1; // force deducting for invalid keys
                VLOG(2) << "invalid apikey: |" << rawkey << "|\n";
            } else {
                VLOG(2) << "apikey: " << rawkey << " data: " << key.data << "\n";
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
                    key.data.credits = credit_limit;
                }
                if (key.data.expires != 0) {
                    if (time(0) >= (time_t)key.data.expires) {
                        state = expired;
                        if (value == 0) value = 1; // force deducting for invalid keys
                        VLOG(2) << "expired apikey: " << rawkey << "\n";
                    }
                }
            }
        }
        // TODO: returning the count in value is really confusing
        query(db, ckey, value);
        return state;
    }

    bool query(const std::string &db, uint64_t key, uint64_t &val, unsigned int timeout_ms=100) {
        packet pkt{};
        pkt.xid = xid++;
        pkt.set_db(db);
        pkt.key = key;
        pkt.value = val;
        nettask t;
        ssize_t nw = sock.sendto(&pkt, sizeof(pkt), saddr);
        if (nw == sizeof(pkt)) {
            tasks[pkt.xid] = t;
            try {
                deadline dl{milliseconds{timeout_ms}};
                // TODO: use timed_recv instead of deadline
                // once rendez has wait_util and wait_for
                //bool success = t.ch.timed_recv(pkt, timeout_ms);
                //if (success) { val = pkt.value; }
                //return success;
                taskstate("waiting for credit-server");
                pkt = t.ch.recv();
                val = pkt.value;
                return true;
            } catch (deadline_reached &) {}
        }
        return false;
    }

    void close() {
        taskcancel(_recv_tid);
    }

    static std::unordered_set<std::string> read_blacklist_file(const std::string &filename) {
        if (filename.empty()) return {};
        // TODO: use std::regex once libstdc++ has fully implemented it
        using boost::regex;
        using boost::match_results;
        regex key_line_re{
                "^[a-zA-Z0-9]+$"};
        std::ifstream gf{filename};
        std::unordered_set<std::string> keys;
        if (gf.is_open()) {
            std::string line;
            while (std::getline(gf, line)) {
                if (line.empty() || line[0] == '#') continue;
                match_results<std::string::const_iterator> result;
                if (regex_match(line, key_line_re)) {
                    VLOG(2) << "adding blacklisted key: " << line;
                    keys.insert(line);
                } else {
                    LOG(ERROR) << "skipping blacklist line: " << line;
                }
            }
        } else {
            LOG(ERROR) << "Could not open " << filename;
        }
        return keys;
    }

    static std::unordered_map<std::string, uint64_t> read_grandfather_file(const std::string &filename)
    {
        if (filename.empty()) return {};
        // TODO: use std::regex once libstdc++ has fully implemented it
        using boost::regex;
        using boost::match_results;
        regex key_line_re{
                "^[a-zA-Z0-9]+$"};
        regex key_limit_line_re{
                "^([a-zA-Z0-9]+)[\\ \\t]+([0-9]+)$"};
        std::unordered_map<std::string, uint64_t> keys;
        std::ifstream gf{filename};
        if (gf.is_open()) {
            std::string line;
            while (std::getline(gf, line)) {
                if (line.empty() || line[0] == '#') continue;
                match_results<std::string::const_iterator> result;
                if (regex_match(line, key_line_re)) {
                    VLOG(2) << "adding grandfather key: " << line;
                    // unlimited
                    keys.insert(std::make_pair(line, (~0)));
                } else if (regex_match(line, result, key_limit_line_re)) {
                    uint64_t limit = boost::lexical_cast<uint64_t>(result[2]);
                    VLOG(2) << "adding grandfather key: " << result[1] << " " << limit;
                    keys.insert(std::make_pair(result[1], limit));
                } else {
                    LOG(ERROR) << "skipping grandfather line: " << line;
                }
            }
        } else {
            LOG(ERROR) << "Could not open " << filename;
        }
        return keys;
    }

private:
    socket_fd sock;
    address saddr;
    uint64_t xid;
    task_map tasks;
    uint64_t _recv_tid;

    std::unordered_map<std::string, uint64_t> _grandfather_keys;
    std::unordered_set<std::string> _blacklist_keys;

    void recv_task() {
        taskname("credit_client::recv_task");
        address faddr;
        packet pkt;
        while (fdwait(sock.fd, 'r')) {
            ssize_t nr = sock.recvfrom(&pkt, sizeof(pkt), faddr);
            if (nr < (ssize_t)sizeof(pkt)) break;
            VLOG(3) << "got packet xid: " << pkt.xid;
            task_map::iterator it = tasks.find(pkt.xid);
            if (it != tasks.end()) {
                it->second.ch.send(std::move(pkt));
                tasks.erase(it);
            }
        }
    }
};
