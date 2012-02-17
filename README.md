rl-proxy
========

rate limiting http proxy server for JSON-based services.

Features
  * HMAC signed keys require no key database for validation
  * Organization ID, Application ID, expiration date, and credit limit can be embedded in keys
  * Translate JSONP requests to non-JSONP requests to backend
  * Count credits based on IP address or key.
  * Provide /credit.json for credits remaining, limit and reset times

Overview
_____

`rl-keygen` is used to generate keys

    $ ./rl-keygen --secret 12345 --expire 1d --org_id=42 --app_id=1 --credits=4000000
    PP3FMF5K6LCYHTRWFIAAAAAAAAAQBXAHIIAAACJ5
    {org_id:42,app_id:1,expires:2012/2/2,flags:0,credits:4000000}

`rl-proxy` sits in front of your caching reverse proxys and application servers

    $ ./rl-proxy --backend=localhost:3000 --secret=12345 --reset-duration 24:00:00 --vhost api.example.com
    $ curl -i http://localhost:8080/credit.json
    HTTP/1.1 200 OK
    Content-Length: 202
    Content-Type: application/json
    Date: Fri, 17 Feb 2012 12:22:19 GMT

    {"response":{"limit":3600,"reset":1329552000,"refresh_in_secs":70661,"remaining":3599},"request":{"parameters":{},"response_type":"json","resource":"credit","url":"http://api.example.com/credit.json"}}

    $ curl -i 'http://localhost:8080/credit.json?apikey=PP3FMF5K6LCYHTRWFIAAAAAAAAAQBXAHIIAAACJ5'
    HTTP/1.1 200 OK
    Content-Length: 256
    Content-Type: application/json
    Date: Fri, 17 Feb 2012 12:24:01 GMT

    {"response":{"limit":4000000,"reset":1329552000,"refresh_in_secs":70559,"remaining":4000000},"request":{"parameters":{},"response_type":"json","resource":"credit","url":"http://api.example.com/credit.json?apikey=PP3FMF5K6LCYHTRWFIAAAAAAAAAQBXAHIIAAACJ5"}}


`credit-server` is the central UDP-based in-memory storage for credits

    $ ./credit-server --reset-duration 24:00:00
