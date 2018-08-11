[![Docker Build](https://img.shields.io/docker/build/mikhailprog/corosocks_srv.svg?maxAge=604800)][hub]: https://hub.docker.com/r/mikhailprog/corosocks_srv

# SOCKS5 server (use coroutines)

A small SOCKS5 server based on coroutines. The server uses coroutine and event libraries to emulate blocking IO. The server supports only CONNECT command.

This server is not about SOCKS5 and even not about the server. It is about coroutines and how to write the code in blocking style but use nonblocking calls and no usual callbacks.

## Build

```
$ make
```

Disable messages:

```
$ make SILENT=1
```

Static build:

```
$ LDFLAGS=-static make 
```

## Usage and run

```
$ ./corosocks_srv -h

usage: corosocks_srv [io_drv] [bind_addr] [bind_port]

    io_drv    : select, poll, epoll
    bind_addr : 0.0.0.0
    bind_port : 1080

$ ./corosocks_srv poll 0.0.0.0 1080
 
```
Set 127.0.0.1:1080 as the SOCKS5 server in your browser (e.g Firefox).


Run a server with username/password authentication.

```
$ PROXY_USER=user PROXY_PASSWD=passwd ./corosocks_srv poll 0.0.0.0 1080
```

Run as a daemon (setsid is available only in Linux):

```
$ (wd=$PWD; cd /; setsid $wd/corosocks_srv poll 0.0.0.0 1081 </dev/null >/dev/null 2>&1 &) &

```


## Building in Docker (Linux/OSX)

`cd` into repo directory.

```
$ docker build --target builder -t corosocks-binary .
$ docker run --rm -v $(PWD):/tempdir/ corosocks-binary cp /usr/src/corosocks/corosocks_srv /tempdir/
```

## Running in Docker

Without authorization interactive.
```
$ docker run -p 3000:1080 --name corosocks mikhailprog/corosocks_srv
```

Without authorization daemonized.
```
$ docker run -d -p 1080:1080 --name corosocks mikhailprog/corosocks_srv
```

With authorization daemonized.
```
$ docker run -d -p 1080:1080 -e PROXY_USER='user' -e PROXY_PASSWD='passwd' --name corosocks mikhailprog/corosocks_srv:latest
```

To stop daemonized container.
```
$ docker rm -f corosocks
```
