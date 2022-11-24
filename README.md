
# SOCKS5 server (use coroutines)

A small SOCKS5 server based on coroutines. The server uses coroutine and event libraries to emulate blocking IO. The server supports only CONNECT command.

This implementation shows how to write the code in a blocking style but use nonblocking calls without callbacks. The server uses some advanced UNIX features to connect to the requested host. The server resolves the requested host in a child process (name resolution can block the process), connects to the resolved address and then passes the socket fd back to the parent (check passfd.c), everything is done within a cororoutine. Also the server provides the flexible mechanism to autorize users with an external program which can implements any scheme (check sample auth.sh). 

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

usage: corosocks_srv [io_drv] [bind_addr] [bind_port] [authenticator ...]

    io_drv    : select, poll, epoll
    bind_addr : 0.0.0.0
    bind_port : 1080

$ ./corosocks_srv poll 0.0.0.0 1080
 
```
Set 127.0.0.1:1080 as the SOCKS5 server in your browser (e.g Firefox).


Run a server with username/password authentication.

```
$ PROXY_USER=user PROXY_PASS=passwd ./corosocks_srv poll 0.0.0.0 1080
```

Run a server with username/password authentication but deligate a check to an external program (check auth.sh for more information):
```
$ PROXY_USER="" PROXY_PASS="" ./corosocks_srv poll 0.0.0.0 1080 ./auth.sh
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
$ docker run -d -p 1080:1080 -e PROXY_USER='user' -e PROXY_PASS='passwd' --name corosocks mikhailprog/corosocks_srv:latest
```

To stop daemonized container.
```
$ docker rm -f corosocks
```
