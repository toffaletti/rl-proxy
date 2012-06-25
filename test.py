#!/opt/python/bin/python2.7

from __future__ import unicode_literals
import sys
import os

import unittest
from subprocess import Popen, call, check_call, PIPE
from urllib import urlencode
import signal
import httplib
import socket
import time
import idea
import json

PROXY_PORT=12380
SECRET='1234'

class TestProxy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # start rl-proxy
        cls.proxy_proc = Popen(['./rl-proxy', '--port', str(PROXY_PORT),
            '--secret', SECRET,
            '--backend', 'localhost:80'])

    @classmethod
    def tearDownClass(cls):
        cls.proxy_proc.send_signal(signal.SIGINT)
        cls.proxy_proc.wait()

    def test_00http(self):
        while True:
            try:
                self.conn = httplib.HTTPConnection('localhost', PROXY_PORT)
                self.conn.request('GET', '/credit.json')
                r = self.conn.getresponse()
                self.assertEqual(200, r.status)
                return
            except socket.error, e:
                if e.errno == 111:
                    time.sleep(1)
                    continue
                raise

if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    unittest.main(testRunner=runner)
