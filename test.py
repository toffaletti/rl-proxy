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
import threading
from BaseHTTPServer import HTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler

PROXY_PORT=12380
CREDIT_PORT=11170
SECRET='1234'

class RequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

def serve_http(httpd):
    httpd.serve_forever()

class TestProxy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # start rl-proxy
        with open('grandfathered_test_keys', 'w+') as f:
            f.write('AAAA\n')
            f.write('AAAB 1\n')
        cls.credit_proc = Popen([
            'valgrind', '--log-file=rlproxy_valgrind.log',
            './credit-server',
            '--port', str(CREDIT_PORT),
            '--reset-duration', '00:00:10',
            ])

        cls.proxy_proc = Popen([
            'valgrind', '--log-file=rlproxy_valgrind.log',
            './rl-proxy',
            '--port', str(PROXY_PORT),
            '--secret', SECRET,
            '--backend', 'localhost:12480',
            '--reset-duration', '00:00:10',
            '--credit-server', 'localhost:%d' % CREDIT_PORT,
            '--credit-limit', '3',
            '--grandfather', 'grandfathered_test_keys',
            ])
        httpd = HTTPServer(('127.0.0.1', 12480), RequestHandler)
        httpd_thread = threading.Thread(target=serve_http, args=(httpd,))
        httpd_thread.daemon = True
        httpd_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.proxy_proc.send_signal(signal.SIGINT)
        cls.proxy_proc.wait()
        cls.credit_proc.send_signal(signal.SIGINT)
        cls.credit_proc.wait()

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

    def test_01_credit_jsonp(self):
        self.conn = httplib.HTTPConnection('localhost', PROXY_PORT)
        self.conn.request('GET', '/credit.json?callback=foo')
        r = self.conn.getresponse()
        self.assertEqual(200, r.status)
        body = r.read()
        self.assertTrue(body.startswith("foo("))

    def test_02_test_credit_deduction_no_key(self):
        self.conn = httplib.HTTPConnection('localhost', PROXY_PORT)

        for remaining in ['2', '1', '0']:
            self.conn.request('GET', '/test.json')
            r = self.conn.getresponse()
            self.assertEqual(200, r.status)
            self.assertEqual(
                    r.getheader('x-ratelimit-remaining', 'bad'),
                    remaining)

        self.conn.request('GET', '/test.json')
        r = self.conn.getresponse()
        self.assertEqual(503, r.status)
        reset_time = float(r.getheader('x-ratelimit-reset', 'bad'))
        sleep = reset_time - time.time()
        self.assertTrue(sleep > 0)
        time.sleep(sleep + 1)

        self.conn.request('GET', '/test.json')
        r = self.conn.getresponse()
        self.assertEqual(200, r.status)

    def test_03_test_credit_deduction_grandfather_unlimited_key(self):
        self.conn = httplib.HTTPConnection('localhost', PROXY_PORT)

        for remaining in ['16777215', '16777215']:
            self.conn.request('GET', '/test.json?apikey=AAAA')
            r = self.conn.getresponse()
            self.assertEqual(200, r.status)
            self.assertEqual(
                    r.getheader('x-ratelimit-remaining', 'bad'),
                    remaining)

    def test_04_test_credit_deduction_grandfather_limited_key(self):
        self.conn = httplib.HTTPConnection('localhost', PROXY_PORT)

        for remaining in ['0']:
            self.conn.request('GET', '/test.json?apikey=AAAB')
            r = self.conn.getresponse()
            self.assertEqual(200, r.status)
            self.assertEqual(
                    r.getheader('x-ratelimit-remaining', 'bad'),
                    remaining)

        self.conn.request('GET', '/test.json?apikey=AAAB')
        r = self.conn.getresponse()
        self.assertEqual(503, r.status)
        reset_time = float(r.getheader('x-ratelimit-reset', 'bad'))
        sleep = reset_time - time.time()
        self.assertTrue(sleep > 0)
        time.sleep(sleep + 1)

        self.conn.request('GET', '/test.json?apikey=AAAB')
        r = self.conn.getresponse()
        self.assertEqual(200, r.status)


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    unittest.main(testRunner=runner)
