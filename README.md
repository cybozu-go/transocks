[![GitHub release](https://img.shields.io/github/release/cybozu-go/transocks.svg?maxAge=60)][releases]
[![GoDoc](https://godoc.org/github.com/cybozu-go/transocks?status.svg)][godoc]
[![Build Status](https://travis-ci.org/cybozu-go/transocks.svg?branch=master)](https://travis-ci.org/cybozu-go/transocks)
[![Go Report Card](https://goreportcard.com/badge/github.com/cybozu-go/transocks)](https://goreportcard.com/report/github.com/cybozu-go/transocks)
[![License](https://img.shields.io/github/license/cybozu-go/transocks.svg?maxAge=2592000)](LICENSE)

transocks - a transparent SOCKS5/HTTP proxy
===========================================

**transocks** is a background service to redirect TCP connections
transparently to a SOCKS5 server or a HTTP proxy server like [Squid][].

Currently, transocks supports only Linux iptables with DNAT/REDIRECT target.

Features
--------

* IPv4 and IPv6

    Both IPv4 and IPv6 are supported.
    Note that `nf_conntrack_ipv4` or `nf_conntrack_ipv6` kernel modules
    must be loaded beforehand.

* SOCKS5 and HTTP proxy (CONNECT)

    We recommend using SOCKS5 server if available.
    Take a look at our SOCKS server [usocksd][] if you are looking for.

    HTTP proxies often prohibits CONNECT method to make connections
    to ports other than 443.  Make sure your HTTP proxy allows CONNECT
    to the ports you want.

* Graceful stop & restart

    * On SIGINT/SIGTERM, transocks stops gracefully.
    * On SIGHUP, transocks restarts gracefully.

* Library and executable

    transocks comes with a handy executable.
    You may use the library to create your own.

Install
-------

Use Go 1.7 or better.

```
go get -u github.com/cybozu-go/transocks/...
```

Usage
-----

`transocks [-h] [-f CONFIG]`

The default configuration file path is `/etc/transocks.toml`.

In addition, transocks implements [the common spec](https://github.com/cybozu-go/cmd#specifications) from [`cybozu-go/cmd`](https://github.com/cybozu-go/cmd).

transocks does not have *daemon* mode.  Use systemd to run it
on your background.

Configuration file format
-------------------------

`transocks.toml` is a [TOML][] file.

`proxy_url` are mandatory.  Other items are optional.

```
# listening address of transocks.
listen = "localhost:1081"    # default is "localhost:1081"

proxy_url = "socks5://10.20.30.40:1080"  # for SOCKS5 server
# proxy_url = "http://10.20.30.40:3128"   # for HTTP proxy server

[log]
filename = "/path/to/file"   # default to stderr
level = "info"               # critical", error, warning, info, debug
format = "json"              # plain, logfmt, json
```

Redirecting connections by iptables
-----------------------------------

Use DNAT or REDIRECT target in OUTPUT chain of the `nat` table.

Save the following example to a file, then execute:
`sudo iptables-restore < FILE`

```
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:TRANSOCKS - [0:0]
-A OUTPUT -p tcp -j TRANSOCKS
-A TRANSOCKS -d 0.0.0.0/8 -j RETURN
-A TRANSOCKS -d 10.0.0.0/8 -j RETURN
-A TRANSOCKS -d 127.0.0.0/8 -j RETURN
-A TRANSOCKS -d 169.254.0.0/16 -j RETURN
-A TRANSOCKS -d 172.16.0.0/12 -j RETURN
-A TRANSOCKS -d 192.168.0.0/16 -j RETURN
-A TRANSOCKS -d 224.0.0.0/4 -j RETURN
-A TRANSOCKS -d 240.0.0.0/4 -j RETURN
-A TRANSOCKS -p tcp -j REDIRECT --to-ports 1081
COMMIT
```

Use *ip6tables* to redirect IPv6 connections.

Library usage
-------------

Read [the documentation][godoc].

License
-------

[MIT](https://opensource.org/licenses/MIT)

[releases]: https://github.com/cybozu-go/transocks/releases
[godoc]: https://godoc.org/github.com/cybozu-go/transocks
[Squid]: http://www.squid-cache.org/
[usocksd]: https://github.com/cybozu-go/usocksd
[TOML]: https://github.com/toml-lang/toml
