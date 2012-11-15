import httplib
import urllib
import socket
import time

class HttpClient:
    """small wrapper around httplib"""

    def __init__(self, host, port):
        self.conn = httplib.HTTPConnection(host, port)
        self.connected = False

    def _ensure_connection(self):
        if self.connected: return
        # loop to sleep while server isn't listening
        while True:
            try:
                self.conn.connect()
                self.connected = True
                return
            except socket.error, e:
                if e.errno == 111:
                    time.sleep(1)
                    continue
                raise

    def request(self, method, url, body='', headers={}):
        self._ensure_connection()
        self.conn.request(method, url, body, headers)
        r = self.conn.getresponse()
        body = r.read()
        return (r, body)

    def get(self, path, **kw):
        if len(kw):
            url = '%s?%s' % (path, urllib.urlencode(kw))
        else:
            url = path
        return self.request('GET', url)

if __name__ == '__main__':
    c = HttpClient('localhost', 13082)
    r = c.get('/test', this='that', one=1, space='this has spaces')
    r.read()
    r = c.get('/test', this='that', one=1, space='this has spaces')
    r.read()

