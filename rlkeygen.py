"""
generate and verify keys for rl-proxy

>>> key_generate("weee", 1, 1, 500, date(1980, 7, 12), 3)
'MMGLFFCSIPWEYDXYAEAAAAAAAAAQB4DZZUJQAAAAAAB7IAIA'
>>> key_verify("weee", 'MMGLFFCSIPWEYDXYAEAAAAAAAAAQB4DZZUJQAAAAAAB7IAIA')
(1L, 1, 500L, datetime.date(1980, 7, 12), 3)
"""

from ctypes import *
from datetime import date
import time

__all__ = ['key_generate', 'key_verify']

lib = cdll.LoadLibrary("libkeygen.so")

KEY_LENGTH = lib.key_length()

def key_generate(secret, org_id, app_id, credits=0, expire_date=None, flags=0):
    """generate an api key with the supplied meta data"""
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
    """verify that an api is valid, returns the embedded meta data if valid, otherwise None"""
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
    import doctest
    doctest.testmod()
