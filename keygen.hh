#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "fw/descriptors.hh"
#include "fw/encoders.hh"

struct expire_date_t {
    uint16_t year;
    uint8_t month;
    uint8_t day;
} __attribute__((packed));

std::ostream &operator <<(std::ostream &o, const expire_date_t &d) {
    o << d.year << "/" << (int)d.month << "/" << (int)d.day;
    return o;
}

static expire_date_t no_expire = {0, 0, 0};

struct apikey {
    uint8_t digest[11];
    uint64_t org_id;
    expire_date_t expires;
    uint16_t flags;

    uint8_t *data() { return (uint8_t *)&org_id; }
    size_t data_size() { return 14; }
} __attribute__((packed));

struct key_engine {
    std::string secret;

    static const size_t keylen = sizeof(apikey);
    static const size_t b32keylen = (sizeof(apikey) + 4) / 5 * 8;

    key_engine(const std::string &secret_) : secret(secret_) {
        ENGINE_load_builtin_engines();
        ENGINE_register_all_complete();
    }

    std::string generate(uint64_t org_id, expire_date_t expires = no_expire , uint8_t flags = 0) {
        apikey key;
        key.org_id = org_id;
        key.expires = expires;
        key.flags = flags;

        unsigned char md[20];
        unsigned int mdlen = sizeof(md);

        HMAC(EVP_sha1(), secret.data(), secret.size(),
            key.data(), key.data_size(), md, &mdlen);

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
            HMAC(EVP_sha1(), secret.data(), secret.size(), key.data(), key.data_size(), md, &mdlen);
            return memcmp(md, key.digest, sizeof(key.digest)) == 0;
        } catch (...) {
            return false;
        }
    }
};
