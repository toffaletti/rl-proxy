#include "keygen.hh"

extern "C" {
    extern size_t key_length();

    extern int key_generate(
            const char *secret,
            uint64_t org_id,
            uint16_t app_id,
            uint32_t credits,
            uint64_t expires,
            uint8_t flags,
            char key[key_engine::b32keylen]
            );

    extern int key_verify(
            const char *secret,
            const char key[key_engine::b32keylen],
            uint64_t *org_id,
            uint16_t *app_id,
            uint32_t *credits,
            uint64_t *expires,
            uint8_t *flags
            );
}

extern "C" {
    size_t key_length() {
        return key_engine::b32keylen;
    }

    int key_generate(
            const char *secret,
            uint64_t org_id,
            uint16_t app_id,
            uint32_t credits,
            uint64_t expires,
            uint8_t flags,
            char key[key_engine::b32keylen]
            )
    {
        key_engine eng{secret};
        memset(key, 0, sizeof(key));
        try {
            std::string k = eng.generate(org_id, app_id, credits, expires, flags);
            memcpy(key, k.data(), k.size());
            return 0;
        } catch (...) {
            return -1;
        }
        return -2;
    }

    int key_verify(
            const char *secret,
            const char key[key_engine::b32keylen],
            uint64_t *org_id,
            uint16_t *app_id,
            uint32_t *credits,
            uint64_t *expires,
            uint8_t *flags
            )
    {
        apikey k;
        key_engine eng{secret};
        bool valid = eng.verify(key, k);
        if (valid) {
            if (org_id)
                *org_id = k.data.org_id;
            if (app_id)
                *app_id = k.data.app_id;
            if (credits)
                *credits = k.data.credits;
            if (expires) {
                *expires = k.data.expires;
            }
            if (flags)
                *flags = k.data.flags;
            return 1;
        }
        return 0;
    }

}
