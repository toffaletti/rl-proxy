#ifndef KEYGEN_HH
#define KEYGEN_HH

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "libten/descriptors.hh"
#include "libten/encoders.hh"
#include <boost/date_time/posix_time/posix_time.hpp>

time_t to_time_t(const boost::posix_time::ptime &t) {
    using namespace boost::posix_time;
    struct tm tt = to_tm(t);
    return mktime(&tt);
}

struct expire_date_t {
    uint16_t year:12;
    uint16_t month:4;
    uint8_t day;
} __attribute__((packed));

static expire_date_t no_expire = {0, 0, 0};

std::ostream &operator <<(std::ostream &o, const expire_date_t &d) {
    o << d.year << "/" << (int)d.month << "/" << (int)d.day;
    return o;
}

struct meta_t {
    uint64_t org_id:48;
    uint64_t app_id:16;
    expire_date_t expires;
    uint32_t flags:8;
    uint32_t credits:24;
} __attribute__((packed));

std::ostream &operator <<(std::ostream &o, const meta_t &m) {
    o << "{org_id:" << m.org_id << ",app_id:" << m.app_id << ",expires:" << m.expires;
    o << ",flags:" << m.flags << ",credits:" << m.credits << "}";
    return o;
}

struct apikey {
    uint8_t digest[10];
    meta_t data;
} __attribute__((packed));

struct key_engine {
    std::string secret;

    static const size_t keylen = sizeof(apikey);
    static const size_t b32keylen = (sizeof(apikey) + 4) / 5 * 8;

    key_engine(const std::string &secret_) : secret(secret_) {
        ENGINE_load_builtin_engines();
        ENGINE_register_all_complete();
    }

    std::string generate(uint64_t org_id,
        uint16_t app_id,
        uint32_t credits = 0,
        expire_date_t expires = no_expire , uint8_t flags = 0)
    {
        apikey key;
        memset(&key, 0, sizeof(key));
        key.data.org_id = org_id;
        if (key.data.org_id != org_id) { throw std::runtime_error("org_id overflow"); }
        key.data.app_id = app_id;
        key.data.expires = expires;
        key.data.flags = flags;
        key.data.credits = credits;

        unsigned char md[20];
        unsigned int mdlen = sizeof(md);

        HMAC(EVP_sha1(), secret.data(), secret.size(),
            (uint8_t *)&key.data, sizeof(key.data), md, &mdlen);

        if (mdlen != sizeof(md)) abort();

        memcpy(key.digest, md, sizeof(key.digest));

        char b32key[b32keylen];
        stlencoders::base32<char>::encode_upper((uint8_t *)&key, &((uint8_t *)&key)[sizeof(key)], b32key);
        return std::string(b32key, b32keylen);
    }

    bool verify(const std::string &b32key, apikey &key) {
        try {
            stlencoders::base32<char>::decode(b32key.begin(), b32key.end(), (uint8_t *)&key);
            unsigned char md[20];
            unsigned int mdlen = sizeof(md);
            HMAC(EVP_sha1(), secret.data(), secret.size(), (uint8_t *)&key.data, sizeof(key.data), md, &mdlen);
            return memcmp(md, key.digest, sizeof(key.digest)) == 0;
        } catch (...) {
            return false;
        }
    }
};

#endif // KEYGEN_HH
