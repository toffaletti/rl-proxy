from ctypes import *
from datetime import date
import time

lib = cdll.LoadLibrary("./libkeygen.so")

KEY_LENGTH = lib.key_length()

def key_generate(secret, org_id, app_id, credits=0, expire_date=None, flags=0):
    key = create_string_buffer(KEY_LENGTH)
    expire_time = 0L
    if expire_date:
        expire_time = long(time.mktime(expire_date.timetuple()))
    status = lib.key_generate(secret, org_id, app_id, credits, expire_time, flags,
            key)
    if status != 0:
        raise Exception("bad")
    return key.raw

def key_verify(secret, key):
    org_id = c_ulonglong()
    app_id = c_ushort()
    credits = c_ulong()
    expire_time = c_ulonglong()
    flags = c_ubyte()
    status = lib.key_verify(secret, key, byref(org_id), byref(app_id),
            byref(credits), byref(expire_time), byref(flags))
    if status:
        return (org_id.value, app_id.value, credits.value,
                date.fromtimestamp(expire_time.value),
                flags.value)
    return None

if __name__ == '__main__':
    key = key_generate("weee", 1, 1, 500, date(1980, 7, 12), 3)
    print key
    print key_verify("weee", key)
