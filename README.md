rl-proxy
========

rate limiting http proxy server for JSON-based services.

Features

  * HMAC signed keys require no key database for validation.
  * Organization ID, Application ID, expiration date, and credit limit can be embedded in keys.
  * Translate JSONP requests to non-JSONP requests on the backend.
  * Strip cache busting headers and query params.
  * Count credits based on IP address or key.
  * Provide /credit.json for credits remaining, limit and reset times.

Overview
_____

`rl-keygen` is used to generate keys

    $ ./rl-keygen --secret=12345 --org_id=42 --app_id=1 --expire=1d --credits=240000
    XQW2MHYHE3NTC2NDFIAAAAAAAAAQBXBHCIAIBKID
    {org_id:42,app_id:1,expires:2012/2/18,flags:0,credits:240000}
    
    $ ./rl-keygen --secret=12345 --org_id=42 --app_id=2 --expire=2000/1/1 --credits=240000
    MVA26DOSEN4FD77CFIAAAAAAAABABUAXAEAIBKID
    {org_id:42,app_id:2,expires:2000/1/1,flags:0,credits:240000}

`rl-proxy` sits in front of your caching reverse proxys and application servers

    $ ./rl-proxy --backend=localhost:3000 --secret=12345 --reset-duration 24:00:00 --vhost api.example.com --port 8800

    $ curl -i http://localhost:8800/credit.json
    HTTP/1.1 200 OK
    Content-Length: 202
    Content-Type: application/json
    Date: Sat, 18 Feb 2012 01:20:58 GMT

    {"response":{"limit":3600,"reset":1329552000,"refresh_in_secs":23942,"remaining":3600},
    "request":{"parameters":{},"response_type":"json","resource":"credit",
    "url":"http://api.example.com/credit.json"}}

    $ curl -i http://localhost:8800/credit.json?apikey=XQW2MHYHE3NTC2NDFIAAAAAAAAAQBXBHCIAIBKID
    HTTP/1.1 200 OK
    Content-Length: 254
    Content-Type: application/json
    Date: Sat, 18 Feb 2012 01:21:23 GMT

    {"response":{"limit":240000,"reset":1329552000,"refresh_in_secs":23917,"remaining":240000},
    "request":{"parameters":{},"response_type":"json","resource":"credit",
    "url":"http://api.example.com/credit.json?apikey=XQW2MHYHE3NTC2NDFIAAAAAAAAAQBXBHCIAIBKID"}}

    $ curl -i http://localhost:8800/credit.json?apikey=MVA26DOSEN4FD77CFIAAAAAAAABABUAXAEAIBKID
    HTTP/1.1 400 Expired Key
    Connection: close
    Content-Length: 0
    Date: Sat, 18 Feb 2012 01:55:31 GMT


`credit-server` is the central UDP-based in-memory storage for credits

    $ ./credit-server --reset-duration 24:00:00
Dependencies
____________

  * cmake >= 2.8
  * g++ >= 4.7
  * libssl-dev >= 0.9.8
  * libboost-dev >= 1.40
  * libboost-date-time-dev >= 1.40
  * libboost-program-options-dev >= 1.40
  * libboost-test-dev >= 1.40
  * ragel >= 6.5
    
Build
_____
    $ git clone https://toffaletti@github.com/toffaletti/rl-proxy.git
    $ cd rl-proxy
    $ git submodule update --init
    $ mkdir build; cd build
    $ cmake ..
    $ make -j4
