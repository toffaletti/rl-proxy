#!/opt/python/bin/python2.7

from __future__ import unicode_literals
import sys
import os

import unittest
from subprocess import Popen, call, check_call, PIPE
import signal
import time
import idea
import json
import threading
from BaseHTTPServer import HTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler
import rlkeygen
from http import HttpClient

PROXY_PORT=12380
CREDIT_PORT=11170
SECRET='1234'

class MyHTTPServer(HTTPServer):
    allow_reuse_address = True

class RequestHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        length = int(self.headers.getheader('content-length'))
        if self.rfile.read(length) == 'hi':
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()
        else:
            self.send_response(500)
            self.send_header('Content-Length', '0')
            self.end_headers()

    def do_GET(self):
        if self.path == "/apikey_required":
            body = "Key Required";
            self.send_response(200)
            self.send_header('Content-Length', len(body))
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()

def serve_http(httpd):
    httpd.serve_forever()

class TestProxyMixin:

    @classmethod
    def setUpClass(cls):
        # start rl-proxy
        with open('grandfathered_test_keys', 'w+') as f:
            f.write('AAAA\n')
            f.write('AAAB 1\n')
        with open('blacklisted_test_keys', 'w+') as f:
            f.write('FFFF\n')
        cls.credit_proc = Popen([
            'valgrind', '--log-file=creditserver_valgrind.log',
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
            '--credit-limit', cls.default_credit_limit,
            '--grandfather', 'grandfathered_test_keys',
            '--blacklist', 'blacklisted_test_keys',
            '--glog-v', '1',
            ])
        cls.httpd = MyHTTPServer(('127.0.0.1', 12480), RequestHandler)
        cls.httpd_thread = threading.Thread(target=serve_http, args=(cls.httpd,))
        cls.httpd_thread.start()
        cls.http = HttpClient('localhost', PROXY_PORT)

    @classmethod
    def tearDownClass(cls):
        cls.proxy_proc.send_signal(signal.SIGINT)
        cls.proxy_proc.wait()
        cls.credit_proc.send_signal(signal.SIGINT)
        cls.credit_proc.wait()
        cls.httpd.shutdown()
        cls.httpd_thread.join()
        del cls.httpd

    def test_00_rlkeygen(self):
        apikey = rlkeygen.key_generate(SECRET, 1, 1, 0)
        meta = rlkeygen.key_verify(SECRET, apikey)
        self.assertTrue(meta != None)
        self.assertEqual(1, meta['org_id'])
        self.assertEqual(1, meta['app_id'])
        self.assertEqual(0, meta['credits'])
        self.assertEqual(None, meta['expires'])

    def test_00_root_pass_through(self):
        r, body = self.http.get('/')
        self.assertEqual(200, r.status)

    def test_00_credit_json(self):
        r, body = self.http.get('/credit.json')
        self.assertEqual(200, r.status)

    def test_01_credit_jsonp(self):
        r, body = self.http.get('/credit.json', callback='foo')
        self.assertEqual(200, r.status)
        self.assertTrue(body.startswith("foo("))

    def test_02_credit_deduction_no_key(self):
        for remaining in ['2', '1', '0']:
            r, body = self.http.get('/test.json')
            self.assertEqual(200, r.status)
            self.assertEqual(remaining,
                    r.getheader('x-ratelimit-remaining', 'bad'))

        r, body = self.http.get('/test.json')
        self.assertEqual(503, r.status)
        reset_time = float(r.getheader('x-ratelimit-reset', 'bad'))
        sleep = reset_time - time.time()
        self.assertTrue(sleep > 0)
        time.sleep(sleep + 1)

        r, body = self.http.get('/test.json')
        self.assertEqual(200, r.status)

    def test_02_post_with_key(self):
        r, body = self.http.post('/test.json', 'hi', apikey='AAAA')
        self.assertEqual(200, r.status)

    def test_credit_deduction_grandfather_unlimited_key(self):

        for remaining in ['16777215', '16777215']:
            r, body = self.http.get('/test.json', apikey='AAAA')
            self.assertEqual(200, r.status)
            self.assertEqual(remaining,
                    r.getheader('x-ratelimit-remaining', 'bad'))
        # check credit.json
        r, body = self.http.get('/credit.json', apikey='AAAA')
        self.assertEqual(200, r.status)
        self.assertEqual('16777215',
                r.getheader('x-ratelimit-remaining', 'bad'))
        js = json.loads(body)
        self.assertEqual(16777215,
                js['response']['remaining'])
        self.assertEqual('16777215',
                r.getheader('x-ratelimit-limit', 'bad'))
        self.assertEqual(16777215,
                js['response']['limit'])

    def test_credit_deduction_grandfather_limited_key(self):
        # check credit.json
        r, body = self.http.get('/credit.json', apikey='AAAB')
        self.assertEqual(200, r.status)
        self.assertEqual('1',
                r.getheader('x-ratelimit-remaining', 'bad'))
        js = json.loads(body)
        self.assertEqual(1,
                js['response']['remaining'])
        self.assertEqual('1',
                r.getheader('x-ratelimit-limit', 'bad'))
        self.assertEqual(1,
                js['response']['limit'])

        for remaining in ['0']:
            r, body = self.http.get('/test.json', apikey='AAAB')
            self.assertEqual(200, r.status)
            self.assertEqual(remaining,
                    r.getheader('x-ratelimit-remaining', 'bad'))

        r, body = self.http.get('/test.json', apikey='AAAB')
        self.assertEqual(503, r.status)
        reset_time = float(r.getheader('x-ratelimit-reset', 'bad'))
        sleep = reset_time - time.time()
        self.assertTrue(sleep > 0)
        time.sleep(sleep + 1)

        r, body = self.http.get('/test.json', apikey='AAAB')
        self.assertEqual(200, r.status)

    def test_blacklist_key(self):
        r, body = self.http.get('/test.json', apikey='FFFF')
        self.assertEqual(403, r.status)

    def test_credit_deduction_generated_key(self):
        # this key will use the default credit limit
        apikey = rlkeygen.key_generate(SECRET, 1, 1, 0)
        r, body = self.http.get('/test.json', apikey=apikey)
        self.assertEqual(200, r.status)
        self.assertEqual('2',
                r.getheader('x-ratelimit-remaining', 'bad'))

        # this key will have a credit limit of 2
        apikey = rlkeygen.key_generate(SECRET, 1, 1, 2)
        r, body = self.http.get('/test.json', apikey=apikey)
        self.assertEqual(200, r.status)
        self.assertEqual('0',
                r.getheader('x-ratelimit-remaining', 'bad'))
        reset_time = float(r.getheader('x-ratelimit-reset', 'bad'))
        r, body = self.http.get('/credit.json', apikey=apikey)
        self.assertEqual(200, r.status)
        self.assertEqual(reset_time,
                float(r.getheader('x-ratelimit-reset', 'bad')))
        js = json.loads(body)
        self.assertEqual('0',
                r.getheader('x-ratelimit-remaining', 'bad'))
        self.assertEqual(0, js['response']['remaining'])
        self.assertEqual(2, js['response']['limit'])


class TestProxy(TestProxyMixin, unittest.TestCase):
    default_credit_limit = '3'


class TestProxyKeyRequired(TestProxyMixin, unittest.TestCase):
    default_credit_limit = '0'

    @classmethod
    def setUpClass(cls):
        # start rl-proxy
        with open('grandfathered_test_keys', 'w+') as f:
            f.write('AAAA\n')
            f.write('AAAB 1\n')
        cls.credit_proc = Popen([
            'valgrind', '--log-file=creditserver_valgrind.log',
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
            '--credit-limit', cls.default_credit_limit,
            '--grandfather', 'grandfathered_test_keys',
            '--glog-v', '1',
            '--custom-errors',
            ])
        cls.httpd = MyHTTPServer(('127.0.0.1', 12480), RequestHandler)
        cls.httpd_thread = threading.Thread(target=serve_http, args=(cls.httpd,))
        cls.httpd_thread.start()
        cls.http = HttpClient('localhost', PROXY_PORT)

    def test_02_credit_deduction_no_key(self):
        r, body = self.http.get('/test.json')
        self.assertEqual(403, r.status)
        self.assertEqual('Apikey required', r.getheader('Warning', ''))
        self.assertEqual('text/plain', r.getheader('Content-Type', ''))
        self.assertEqual('Key Required', body)

    def test_credit_deduction_generated_key(self):
        # credit limit of 3 inside the key
        apikey = rlkeygen.key_generate(SECRET, 1, 1, 3)
        r, body = self.http.get('/test.json', apikey=apikey)
        self.assertEqual(200, r.status)
        self.assertEqual('2',
                r.getheader('x-ratelimit-remaining', 'bad'))

        # this key will have a credit limit of 2
        apikey = rlkeygen.key_generate(SECRET, 1, 1, 2)
        r, body = self.http.get('/test.json', apikey=apikey)
        self.assertEqual(200, r.status)
        self.assertEqual('0',
                r.getheader('x-ratelimit-remaining', 'bad'))
        reset_time = float(r.getheader('x-ratelimit-reset', 'bad'))
        r, body = self.http.get('/credit.json', apikey=apikey)
        self.assertEqual(200, r.status)
        self.assertEqual(reset_time,
                float(r.getheader('x-ratelimit-reset', 'bad')))
        js = json.loads(body)
        self.assertEqual('0',
                r.getheader('x-ratelimit-remaining', 'bad'))
        self.assertEqual(0, js['response']['remaining'])
        self.assertEqual(2, js['response']['limit'])



if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    unittest.main(testRunner=runner)
