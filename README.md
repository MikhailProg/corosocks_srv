# SOCKS5 server (use coroutines)

A small SOCKS5 server based on coroutines. The server uses coroutine and event libraries to emulate blocking IO. The server supports only CONNECT command without authentication.

This server is not about SOCKS5 and even not about the server. It is about coroutines and how to write the code in blocking style but use unblocking calls without usual callbacks.

## Build

```
$ make
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

Run as a daemon:

```
$ (wd=$PWD; cd /; setsid $wd/corosocks_srv poll 0.0.0.0 1081 </dev/null >/dev/null 2>/dev/null) &

```

