#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#include "socks5.h"
#include "loop.h"
#include "inet.h"
#include "coroutine.h"
#include "passfd.h"
#include "common.h"

#define CONNECT_TIMEOUT	5000
#define ADDR		"0.0.0.0"
#define PORT		"1080"

#define STRINIT(s, a1, a2)      ((s)->p = (a1), (s)->n = (a2))
#define STREQU(s1, s2)          ((s1)->n == (s2)->n && \
					!memcmp((s1)->p, (s2)->p, (s1)->n))
typedef struct {
	char	*p;
	size_t 	n;
} Str;

static struct {
	Str	user;
	Str	pass;
} socks5_auth_user;

static int (*socks5_auth_methods[256])(Fd);
static int socks5_auth_type;

static int fd_nonblock(Fd fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return -1;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ? -1 : 0;
}

static void loop_handler(Fd fd, LoopEvent event, void *opaque)
{
	UNUSED(fd);
	UNUSED(event);
	coroutine_resume((Coroutine *)opaque);
}

static ssize_t
coro_io(ssize_t (*op)(int, void *, size_t, int), LoopEvent event,
		int fd, void *buf, size_t len, int flags)
{
	ssize_t n;
	while ((n = op(fd, buf, len, flags)) < 0) {
		if (!SOFT_ERROR)
			break;
		if (loop_fd_add(fd, event, loop_handler, coroutine_self()) < 0)
			abort();
		coroutine_yield(NULL);
		if (loop_fd_del(fd) < 0)
			abort();
	}

	return n;
}

static ssize_t coro_send(int fd, const void *buf, size_t len, int flags)
{
	return coro_io((ssize_t (*)(int, void *, size_t, int))send,
			LOOP_WR, fd, (void *)buf, len, flags);
}

static ssize_t coro_recv(int fd, void *buf, size_t len, int flags)
{
	return coro_io(recv, LOOP_RD, fd, buf, len, flags);
}

static int coro_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
	int afd;

	while ((afd = accept(fd, addr, addrlen)) < 0) {
		if (!SOFT_ERROR)
			break;
		if (loop_fd_add(fd, LOOP_RD, loop_handler, coroutine_self()) < 0)
			abort();
		coroutine_yield(NULL);
		if (loop_fd_del(fd) < 0)
			abort();
	}

	return afd;
}

static int connect_timeout(const char *host, const char *port, int timeout)
{
	socklen_t elen;
	struct pollfd fds;
	int fd, rc, err;

	/* Connect in nonblock mode. */
	if ((fd = tcp_connect(host, port, fd_nonblock)) < 0)
		return -1;
	/* Connected immediately. */
	if (errno != EINPROGRESS)
		return fd;
	
	fds.fd = fd;
	fds.events = POLLOUT;
	do {
		rc = poll(&fds, 1, timeout);
	} while (rc < 0 && errno == EINTR);

	/* Timeout or poll error. */
	if (rc <= 0) {
		if (!rc) {
			errno = ETIMEDOUT;
			WARNX("connect timeout fd=%d", fd);
		}
		close(fd);
		return -1;
	}

	elen = sizeof(err);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0) {
		err = errno;
		WARN("getsockopt");
	} else if (err) {
		errno = err; 
		WARN("connect (deferred)");
	} else {
		WARNX("fd=%d connected", fd);
	}

	if (err) {
		close(fd);
		return -1;
	}
	return fd;
}

static int connect_async(const char *host, const char *port)
{
	sigset_t mask, omask;
	int fd, pair[2], i, rc = EXIT_SUCCESS;
	struct rlimit rlim;

	UNUSED(rlim);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0)
		return -1;

	if (fd_nonblock(pair[0]) < 0)
		goto err0;

	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, &omask);

	switch (fork()) {
	case -1:
		goto err1;
	case  0:
		close(pair[0]);
#if 0
		if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
			_exit(EXIT_FAILURE);
		for (i = 3; i < (int)rlim.rlim_cur; i++)
			if (pair[1] != i)
				close(i);
#endif
		for (i = 1; i < NSIG; i++)
			signal(i, SIG_DFL);
		sigemptyset(&mask);
		sigprocmask(SIG_SETMASK, &mask, NULL);
		if ((fd = connect_timeout(host, port, CONNECT_TIMEOUT)) < 0 ||
				send_fd(pair[1], fd) < 0)
			rc = EXIT_FAILURE;
		_exit(rc);
	}

	sigprocmask(SIG_SETMASK, &omask, NULL);
	close(pair[1]);
	return pair[0];
err1:
	sigprocmask(SIG_SETMASK, &omask, NULL);
err0:
	close(pair[0]);
	close(pair[1]);
	return -1;
}

static int coro_connect(const char *host, const char *port)
{
        int fd, un;

	if ((un = connect_async(host, port)) < 0)
		return -1;

	while ((fd = recv_fd(un)) < 0) {
		if (!SOFT_ERROR) {
			close(un);
			return -1;
		}
		if (loop_fd_add(un, LOOP_RD, loop_handler, coroutine_self()) < 0)
			abort();
		coroutine_yield(NULL);
		if (loop_fd_del(un) < 0)
			abort();
	}

	close(un);
	if (fd_nonblock(fd) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static ssize_t coro_send_all(int fd, const void *buf, size_t len, int flags)
{
	size_t off = 0, m = len;
	ssize_t n;

	while (len) {
		if ((n = coro_send(fd, buf + off, len, flags)) < 0) {
			if (!SOFT_ERROR)
				return -1;
			continue;
		}
		off += n;
		len -= n;
	}

	return m;
}

static int socks5_auth_noauth(Fd fd)
{
	UNUSED(fd);
	return 0;
}

static int socks5_auth_username(Fd fd)
{
	/* ver 1 byte | ulen 1 byte | user | plen 1 byte | pass */
	unsigned char buf[513];
	Str user, pass;
	size_t ulen, plen;
	ssize_t n;
	int ok = 0;

	if ((n = coro_recv(fd, buf, sizeof(buf), 0)) < 0)
		return -1;
	/* Sanity checks. */
	if (n < 5 || buf[0] != 1)
		goto out;
	n -= 3;
	if (!(ulen = buf[1]) || ulen >= (size_t)n)
		goto out;
	n -= ulen;
	if (!(plen = buf[2+ulen]) || plen > (size_t)n)
		goto out;

	STRINIT(&user, (char *)&buf[2], ulen);
	STRINIT(&pass, (char *)&buf[2+ulen+1], plen);

	if (STREQU(&socks5_auth_user.user, &user) &&
	    STREQU(&socks5_auth_user.pass, &pass))
		ok = 1;
out:
	buf[0] = 1;
	buf[1] = ok ? 0 : 1;

	if (coro_send_all(fd, buf, 2, 0) < 0)
		return -1;

	return ok ? 0 : -1;
}

static int socks5_negotiate(Fd fd)
{
	unsigned char buf[1024], *p = buf;
	unsigned int n = 0, i;
	ssize_t len;
	int ok;

	len = coro_recv(fd, buf, sizeof(buf), 0);
	if (len < 0 || len < 2)
		return -1;
	/* ver 1 byte | nmethods 1 byte | nmethods bytes */
	if (p[0] != SOCKS5 || (n = p[1]) == 0 || len != n + 2)
		return -1;
	p += 2;
	for (i = 0; i < n; i++)
		if (p[i] == socks5_auth_type)
			break;
	ok = i != n;
	buf[0] = SOCKS5;
	buf[1] = ok ? socks5_auth_type : SOCKS5_AUTH_NOMETHOD;
	if (coro_send_all(fd, buf, 2, 0) < 0)
		return -1;
	if (ok)
		WARNX("negotiate done");
	return ok ? 0 : -1;
}

static int socks5_reply(Fd fd, unsigned char rc)
{
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	unsigned char buf[16];

	getsockname(fd, (struct sockaddr *)&sin, &slen);
	buf[0] = SOCKS5;
	buf[1] = rc;
	buf[2] = 0;
	buf[3] = SOCKS5_ATYP_IPV4;
	memcpy(buf + 4, &sin.sin_addr.s_addr, 4);
	memcpy(buf + 8, &sin.sin_port, 2);

	return coro_send_all(fd, buf, 10, 0) < 0 ? -1 : 0;
}

static int socks5_request(Fd fd)
{
	unsigned char buf[1024], *p = buf, rc;
	unsigned int m, n, atype;
	struct in_addr addr;
	char sport[16];
	uint16_t port;
	char *host;
	ssize_t len;
	int cfd;

	len = coro_recv(fd, buf, sizeof(buf), 0);
	if (len < 0 || len < 5)
		return -1;
	/* ver 1 byte | cmd 1 byte | rsv 1 byte | atype 1 byte | ... */
#define CHECK_CMD(v)	((v) == SOCKS5_CMD_CONNECT)
#define CHECK_ATYPE(v)	((v) == SOCKS5_ATYP_IPV4 || (v) == SOCKS5_ATYP_NAME)
	if (p[0] != SOCKS5 || !CHECK_CMD(p[1]) ||
	    p[2] != 0 || !CHECK_ATYPE(p[3]))
		return -1;
#undef CHECK_ATYPE
#undef CHECK_CMD
	atype = p[3];
	m = p[4];
	n = 4 + (atype == SOCKS5_ATYP_IPV4 ? 6 : m + 1 + 2);
	if (len != n)
		return -1;

	if (atype == SOCKS5_ATYP_IPV4) {
		memcpy(&port, p + 8, 2);
		memcpy(&addr.s_addr, p + 4, sizeof(in_addr_t));
		host = inet_ntoa(addr);
	} else {
		host = (char *)p + 5;
		memcpy(&port, host + m, 2);
		host[m] = '\0';
	}

	port = ntohs(port);
	WARNX("fd=%d, req connect: %s:%u", fd, host, port);
	snprintf(sport, sizeof(sport), "%d", port);

	/* In case SOCKS5_ATYP_NAME it takes time to resolve
	 * the address then srv will be blocked, so we do connection
	 * in the child process and then receive FD via cmsg. */
	cfd = coro_connect(host, sport);
	rc = cfd != -1 ? SOCKS5_REP_SUCCESS : SOCKS5_REP_UNKNOWN;
	if (socks5_reply(fd, rc) < 0) {
		if (cfd != -1)
			close(cfd);
		return -1;
	}
	
	return cfd;
}

static void fds_fini(int fds0[2], int fds1[2])
{
	WARNX("fd=%d -> fd=%d is gone", fds0[0], fds0[1]);
	close(fds0[0]);
	if (fds0[1] != -1)
		close(fds0[1]);
	if (fds1) {
		if (fds1[0] != -1)
			close(fds1[0]);
		if (fds1[1] != -1)
			close(fds1[1]);
	}
}

static void rdwr_loop(void *opaque)
{
	unsigned char buf[65536];
	int *p = opaque, fds[2] = { p[0], p[1] };
	ssize_t n;

	while ((n = coro_recv(fds[0], buf, sizeof(buf), 0)) > 0)
		if (coro_send_all(fds[1], buf, n, 0) < 0)
			goto out;

	if (!n) {
		/* Keep the connection half closed. */
		shutdown(fds[1], SHUT_WR);
	} else {
out:		/* Invalidate sockets in case of recv or send error. */
		shutdown(fds[0], SHUT_RDWR);
		shutdown(fds[1], SHUT_RDWR);
	}

	fds_fini(fds, NULL);
}

static void socks5_entry(void *opaque)
{
	int afd = (intptr_t)opaque, cfd;
	int fds[2][2] = { { afd, -1 }, { -1, -1} };
	int (*socks5_auth)(Fd) = socks5_auth_methods[socks5_auth_type];
	Coroutine *co;

	/* The idea is to establish the connection with the remote side.
	 * And then do data exchange in two coroutines, both coroutines
	 * use the same function for IO (rdwr_loop). The first should
	 * read from AFD to CFD, the second from CFD to AFD. */
	if (socks5_negotiate(afd) < 0 || socks5_auth(afd) < 0 ||
		(fds[0][1] = cfd = socks5_request(afd)) < 0 ||
			(fds[1][0] = dup(cfd)) < 0 ||
	    		(fds[1][1] = dup(afd)) < 0 || 
				!(co = coroutine_create(0, rdwr_loop, fds[1]))) {
		fds_fini(fds[0], fds[1]);
		return;
	}

	WARNX("RDWR: fd=%d -> fd=%d, fd=%d -> fd=%d",
			fds[0][0], fds[0][1], fds[1][0], fds[1][1]);

	coroutine_detach(co);
	coroutine_resume(co);
	rdwr_loop(fds[0]);
}

static void srv_loop(void *opaque)
{
	int fd = (intptr_t)opaque, afd;
	struct sockaddr_storage ss;
	socklen_t slen;
	Coroutine *co;

	for (;;) {
		slen = sizeof(ss);
		afd = coro_accept(fd, (struct sockaddr *)&ss, &slen);
		if (afd < 0) {
			if (!SOFT_ERROR)
				WARN("accept() failed");
			continue;
		}
		
		if (fd_nonblock(afd) < 0) {
			WARN("fd_nonblock() failed");
			close(afd);
			continue;
		}

		WARNX("accepted fd=%d", afd);
		co = coroutine_create(0, socks5_entry, (void *)(intptr_t)afd);
		if (!co) {
			WARNX("coroutine_create() failed");
			close(afd);
			continue;
		}

		coroutine_detach(co);
		coroutine_resume(co);
	}
}

static void socks5_auth_init(void)
{
	char *u, *p; 
	size_t ulen, plen;

	socks5_auth_methods[SOCKS5_AUTH_NOAUTH]   = socks5_auth_noauth;
	socks5_auth_methods[SOCKS5_AUTH_USERNAME] = socks5_auth_username;

	socks5_auth_type = SOCKS5_AUTH_NOAUTH;

	if ((u = getenv("PROXY_USER")) &&
		(p = getenv("PROXY_PASSWD")) &&  
			(ulen = strlen(u)) && (plen = strlen(p))) {
		socks5_auth_type = SOCKS5_AUTH_USERNAME;
		STRINIT(&socks5_auth_user.user, u, ulen);
		STRINIT(&socks5_auth_user.pass, p, plen);
	}   
}

static void sigall(int signo)
{
	if (signo == SIGCHLD)
		while (waitpid(-1, NULL, WNOHANG) > 0) ;
	else
		loop_quit();
}

static void usage(void)
{
	extern const char *const __progname;
	fprintf(stderr, "\n"
			"usage: %s [io_drv] [bind_addr] [bind_port]\n"
			"\n"
			"    io_drv    : select, poll"
#ifdef HAVE_EPOLL
			", epoll"
#endif
			"\n"
			"    bind_addr : %s\n"
			"    bind_port : %s\n"
			"\n", __progname, ADDR, PORT);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	char *addr, *port;
	struct sigaction sa;
	struct rlimit rlim;
	LoopDrvType drv;
	Coroutine *srv;
	int fd;

	if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")))
		usage();

	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max == RLIM_INFINITY ?
					rlim.rlim_cur : rlim.rlim_max;
		setrlimit(RLIMIT_NOFILE, &rlim);
	}

	drv  = argc > 1 ? !strcmp(argv[1], "select") ? LOOP_DRV_SELECT :
			  !strcmp(argv[1], "poll")   ? LOOP_DRV_POLL :
#ifdef HAVE_EPOLL
			  !strcmp(argv[1], "epoll")  ? LOOP_DRV_EPOLL :
#endif
				LOOP_DRV_DEFAULT : LOOP_DRV_DEFAULT;
	addr = argc > 2 ? argv[2] : ADDR;
	port = argc > 3 ? argv[3] : PORT;

	socks5_auth_init();
	memset(&sa, 0, sizeof(sa));
	sigfillset(&sa.sa_mask);
	sa.sa_handler = sigall;

	signal(SIGPIPE, SIG_IGN);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGCHLD, &sa, NULL);

	if ((fd = tcp_listen(addr, port)) < 0)
		ERR(EXIT_FAILURE, "tcp_listen() failed");
	if (fd_nonblock(fd) < 0)
		ERR(EXIT_FAILURE, "fd_nonblock() failed");
	if (loop_init(drv) < 0)
		ERRX(EXIT_FAILURE, "loop_init() failed");

	srv = coroutine_create(0, srv_loop, (void *)(intptr_t)fd);
	coroutine_resume(srv);

	loop_run();

	coroutine_destroy(&srv);
	loop_fini();
	close(fd);

	return EXIT_SUCCESS;
}

