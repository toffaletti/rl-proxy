#include "keygen.hh"

extern "C" {
    extern int key_generate(
            const char *secret,
            uint64_t org_id,
            uint16_t app_id,
            uint32_t credits,
            time_t expire_date,
            uint8_t flags,
            char key[40]
            );

    extern int key_verify(
            const char *secret,
            const char key[40],
            uint64_t *org_id,
            uint16_t *app_id,
            uint32_t *credits,
            time_t *expire_date,
            uint8_t *flags
            );
}

extern "C" {
    int key_generate(
            const char *secret,
            uint64_t org_id,
            uint16_t app_id,
            uint32_t credits,
            time_t expire_time,
            uint8_t flags,
            char key[40]
            )
    {
        key_engine eng(secret);
        memset(key, 0, sizeof(key));
        try {
            expire_date_t expires = no_expire;
            if (expire_time) {
                struct tm t = {};
                gmtime_r(&expire_time, &t);
                expires.year = t.tm_year;
                expires.month = t.tm_mon;
                expires.day = t.tm_mday;
            }
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
            const char key[40],
            uint64_t *org_id,
            uint16_t *app_id,
            uint32_t *credits,
            time_t *expire_date,
            uint8_t *flags
            )
    {
        apikey k;
        key_engine eng(secret);
        bool valid = eng.verify(key, k);
        if (valid) {
            if (org_id)
                *org_id = k.data.org_id;
            if (app_id)
                *app_id = k.data.app_id;
            if (credits)
                *credits = k.data.credits;
            if (expire_date) {
                struct tm t = {};
                t.tm_year = k.data.expires.year;
                t.tm_mon = k.data.expires.month;
                t.tm_mday = k.data.expires.day;
                *expire_date = mktime(&t);
            }
            if (flags)
                *flags = k.data.flags;
            return 1;
        }
        return 0;
    }

}
