# socks5d
SOCKS5 proxy server implementation in D

[![Build Status](https://travis-ci.org/nexor/socks5d.svg?branch=master)](https://travis-ci.org/nexor/socks5d)

Project is under heavy development.

## Implemented features

Implemented authentication methods: No authentication, Username/password

TBD: GSS-API

Implemented connect commands: CONNECT

TBD: BIND, UDP ASSOCIATE

Implemented addressing types: IP v4 address, DOMAINNAME.

TBD: IP v6 address

## Building

Socks5d is written using D language and dub package manager.

Compiling the application in debug mode:
```
dub build
```

Compiling the application in release mode:
```
dub build -b release
```
