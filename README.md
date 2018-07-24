# SOCKS5 server (use coroutines)

A small SOCKS5 server based on coroutines. The server uses coroutine and event libraries to emulate blocking IO. The server supports only CONNECT command without authentication.

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

