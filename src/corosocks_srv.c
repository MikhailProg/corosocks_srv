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
#include <paths.h>
#include <poll.h>
#include <errno.h>

#include "socks5.h"
#include "loop.h"
#include "inet.h"
#include "coroutine.h"
#include "passfd.h"
#include "common.h"
#include "config.h"
#include "cache.h"

#ifndef COROUTINE_CACHE_INIT_SIZE
#  define COROUTINE_CACHE_INIT_SIZE	64
#endif
#define CONNECT_TIMEOUT		5000

#define STRINIT(s, a1, a2)      ((s)->p = (a1), (s)->n = (a2))
#define STREQU(s1, s2)          ((s1)->n == (s2)->n && \
					!memcmp((s1)->p, (s2)->p, (s1)->n))
typedef struct {
	char	*p;
	size_t 	n;
} Str;

typedef struct {
	const char	*ip;
	const Str	*u;
	const Str	*p;
} Socks5Auth;

typedef struct {
	const char	*host;
	const char	*port;
} ConnectOpt;

static Cache		coroutine_cache;
static int		socks5_auth_type;
static Str		socks5_user;
static Str		socks5_pass;
static char		**socks5_auth_prog;
static int		(*socks5_auth_methods[256])(Fd);

static int fd_cloexec(Fd fd)
{
	int flags;
	return ((flags = fcntl(fd, F_GETFD)) < 0 ||
			fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) ? -1 : 0;
}

/* All fds in the program are nonblocked, also set CLOEXEC here. */
static int fd_nonblock(Fd fd)
{
	int flags;
	return ((flags = fcntl(fd, F_GETFL)) < 0 ||
			fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
				fd_cloexec(fd) < 0) ? -1 : 0;
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

static Fd chld_run(void (*run)(Fd fd, void *opaque), void *opaque)
{
	sigset_t mask, omask;
	struct rlimit rlim = {0};
	int i, fds[2];

	UNUSED(rlim);
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0)
		return -1;

	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, &omask);

	switch (fork()) {
	case -1:
		sigprocmask(SIG_SETMASK, &omask, NULL);
		close(fds[0]);
		close(fds[1]);
		return -1;
	case  0:
		close(fds[0]);
#if 0
		if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
			_exit(EXIT_FAILURE);
		for (i = 3; i < (int)rlim.rlim_cur; i++)
			if (fds[1] != i)
				close(i);
#endif
		for (i = 1; i < NSIG; i++)
			signal(i, SIG_DFL);
		sigemptyset(&mask);
		sigprocmask(SIG_SETMASK, &mask, NULL);
		run(fds[1], opaque);
		_exit(EXIT_FAILURE);
	}

	sigprocmask(SIG_SETMASK, &omask, NULL);
	close(fds[1]);
	return fds[0];
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

static void connector(Fd un, void *opaque)
{
	ConnectOpt *opt = opaque;
	int fd, rc = EXIT_SUCCESS;

	fd = connect_timeout(opt->host, opt->port, CONNECT_TIMEOUT);
	if (fd < 0 || send_fd(un, fd) < 0)
		rc = EXIT_FAILURE;
	_exit(rc);
}


static int coro_connect(const char *host, const char *port)
{
	ConnectOpt opt = { host, port };
	int fd, un;

	/* Since a host may point to DNS name we connect in a child process,
	 * so a resolver will not block the server. */
	if ((un = chld_run(connector, &opt)) < 0)
		return -1;

	if (fd_nonblock(un) < 0) {
		close(un);
		return -1;
	}

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

static void authenticator(Fd un, void *opaque)
{
	Socks5Auth *auth = opaque;
	char user[256], pass[256];
	int null;

	/* Set user and password variables if they are provided. */
	if (auth->u && auth->p) {
		memcpy(user, auth->u->p, auth->u->n);
		user[auth->u->n] = 0;
		memcpy(pass, auth->p->p, auth->p->n);
		pass[auth->p->n] = 0;
		if (setenv(PROXY_USER, user, 1) < 0 ||
		    setenv(PROXY_PASS, pass, 1) < 0)
			_exit(EXIT_FAILURE);
	}
	/* Also export a client ip address. */
	if (setenv(PROXY_USER_IP, auth->ip, 1) < 0  ||
	    (null = open(_PATH_DEVNULL, O_RDWR)) < 0)
		_exit(EXIT_FAILURE);

	dup2(null, STDIN_FILENO);
	dup2(un, STDOUT_FILENO);
	dup2(null, STDERR_FILENO);
	close(null);
	close(un);

	execvp(socks5_auth_prog[0], socks5_auth_prog);
	_exit(EXIT_FAILURE);
}

static int autenticate(Fd fd, const Str *u, const Str *p)
{
	Socks5Auth auth = { NULL, u, p };
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	char res[2];
	int ok = 0;
	Fd un;

	if (getpeername(fd, (struct sockaddr *)&sin, &slen) < 0)
		return -1;

	auth.ip = inet_ntoa(sin.sin_addr);
	/* Run an authenticator. */
	if ((un = chld_run(authenticator, &auth)) < 0)
		return -1;

	if (fd_nonblock(un) < 0) {
		close(un);
		return -1;
	}
	/* Expect "y" as a success result. */
	if (coro_recv(un, res, sizeof(res), 0) == 2 &&
	    (res[1] == '\n' || res[1] == '\0')) {
		res[1] = '\0';
		if (strcmp(res, "y") == 0)
			ok = 1;
	}

	close(un);
	return ok ? 0 : -1;
}

static int socks5_auth_noauth(Fd fd)
{
	/* With NOAUTH we can check only a client ip address. */
	return socks5_auth_prog ? autenticate(fd, NULL, NULL) : 0;
}

static int socks5_auth_username(Fd fd)
{
	/* ver 1 byte | ulen 1 byte | user | plen 1 byte | pass. Max 513 bytes. */
	unsigned char buf[513], *p = buf;
	size_t ulen, plen, n = 0;
	Str user, pass;
	ssize_t m;
	int ok = 0;

	for (;;) {
		if ((m = coro_recv(fd, buf+n, sizeof(buf)-n, 0)) <= 0)
			return -1;
		n += m;
		if (n > 1 && p[0] != 1)
			return -1;
		/* Partial read. */
		if (n < 2)
			continue;
		if ((ulen = p[1]) == 0)
			return -1;
		/* Partial read. */
		if (n < 2 + ulen + 1)
			continue;
		if ((plen = p[2+ulen]) == 0 || n > (2 + ulen + 1 + plen))
			return -1;
		/* Partial read. */
		if (n < 2 + ulen + 1 + plen)
			continue;
		else
			break;
	}

	STRINIT(&user, (char *)&p[2], ulen);
	STRINIT(&pass, (char *)&p[2+ulen+1], plen);

	if (STREQU(&socks5_user, &user) && STREQU(&socks5_pass, &pass))
		ok = 1;
	else if (socks5_auth_prog)
		ok = autenticate(fd, &user, &pass) < 0 ? 0 : 1;

	buf[0] = 1;
	buf[1] = ok ? 0 : 1;
	if (coro_send_all(fd, buf, 2, 0) < 0)
		return -1;

	return ok ? 0 : -1;
}

static int socks5_negotiate(Fd fd)
{
	/* ver 1 byte | nmethods 1 byte | nmethods bytes. Max 257 bytes.*/
	unsigned char buf[257], *p = buf;
	size_t i, nmeth, n = 0;
	ssize_t m;
	int ok;

	for (;;) {
		if ((m = coro_recv(fd, buf+n, sizeof(buf)-n, 0)) <= 0)
			return -1;
		n += m;
		nmeth = 0;
		/* Sanity checks. */
		if ((n > 0 && p[0] != SOCKS5) ||
		    (n > 1 && ((nmeth = p[1]) == 0 || n > nmeth + 2)))
			return -1;
		/* Partial read. */
		if (n < nmeth + 2)
			continue;
		else
			break;
	}

	p += 2;
	for (i = 0; i < nmeth; i++)
		if (p[i] == socks5_auth_type)
			break;
	ok = i != nmeth;

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

	if (getsockname(fd, (struct sockaddr *)&sin, &slen) < 0)
		return -1;
	buf[0] = SOCKS5;
	buf[1] = rc;
	buf[2] = 0;
	buf[3] = SOCKS5_ATYP_IPV4;
	memcpy(buf + 4, &sin.sin_addr.s_addr, 4);
	memcpy(buf + 8, &sin.sin_port, 2);

	return coro_send_all(fd, buf, 10, 0) < 0 ? -1 : 0;
}

static Fd socks5_request(Fd fd)
{
	/* ver 1 byte | cmd 1 byte | rsv 1 byte | atype 1 byte | ... | port 2 bytes
	 * SOCKS5_ATYP_NAME 1 byte len + 255 FQDN: Max 262 bytes. */
	unsigned char buf[262], *p = buf, rc;
	size_t n = 0, alen, len;
	struct in_addr addr;
	char *host, sport[16];
	int atype, cfd;
	uint16_t port;
	ssize_t m;

	for (;;) {
		if ((m = coro_recv(fd, buf+n, sizeof(buf)-n, 0)) <= 0)
			return -1;
		n += m;
		/* Sanity checks. */
#define CHECK_CMD(v)	((v) == SOCKS5_CMD_CONNECT)
#define CHECK_ATYPE(v)	((v) == SOCKS5_ATYP_IPV4 || (v) == SOCKS5_ATYP_NAME)
		if ((n > 0 && p[0] != SOCKS5) ||
		    (n > 1 && !CHECK_CMD(p[1])) ||
		    (n > 2 && p[2] != 0) ||
		    (n > 3 && !CHECK_ATYPE(p[3])))
			return -1;
#undef CHECK_ATYPE
#undef CHECK_CMD
		/* Partial read. */
		if (n < 5)
			continue;
		atype = p[3];
		alen  = p[4]; /* only for SOCKS5_ATYP_NAME */
		len = 4 + (atype == SOCKS5_ATYP_IPV4 ? 6 : 1 + alen + 2);
		/* Partial read. */
		if (n < len)
			continue;
		else if (n > len)
			return -1;
		else
			break;
	}

	if (atype == SOCKS5_ATYP_IPV4) {
		memcpy(&port, p + 8, 2);
		memcpy(&addr.s_addr, p + 4, sizeof(in_addr_t));
		host = inet_ntoa(addr);
	} else {
		memcpy(&port, p + 5 + alen, 2);
		host = (char *)p + 5;
		host[alen] = '\0';
	}

	port = ntohs(port);
	WARNX("fd=%d, req connect: %s:%u", fd, host, port);
	snprintf(sport, sizeof(sport), "%d", port);

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

static void dummy_entry(void *opaque)
{
	UNUSED(opaque);
	abort();
}

static CacheItem *coroutine_item_alloc(void *opaque)
{
	UNUSED(opaque);
	return (CacheItem *)coroutine_create(0, dummy_entry, NULL);
}

static void coroutine_item_free(CacheItem *item)
{
	coroutine_destroy((Coroutine **)&item);
}

static Coroutine *coroutine_cache_get(void (*entry)(void *opaque), void *opaque)
{
	Coroutine *co = (Coroutine *)cache_get(&coroutine_cache);

	if (co) {
		coroutine_init(co, entry, opaque);
	}

	return co;
}

static int coroutine_back_to_cache(Coroutine *co)
{
	coroutine_on_destroy(co, NULL);
	cache_put(&coroutine_cache, (CacheItem *)co);
	return 0;
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
				fd_cloexec(fds[1][0]) < 0 ||
				fd_cloexec(fds[1][1]) < 0 ||
			!(co = coroutine_cache_get(rdwr_loop, fds[1]))) {
		fds_fini(fds[0], fds[1]);
		return;
	}

	WARNX("RDWR: fd=%d -> fd=%d, fd=%d -> fd=%d",
			fds[0][0], fds[0][1], fds[1][0], fds[1][1]);

	coroutine_on_destroy(co, coroutine_back_to_cache);
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
		co = coroutine_cache_get(socks5_entry, (void *)(intptr_t)afd);
		if (!co) {
			WARNX("coroutine_create() failed");
			close(afd);
			continue;
		}

		coroutine_on_destroy(co, coroutine_back_to_cache);
		coroutine_detach(co);
		coroutine_resume(co);
	}
}

static void socks5_auth_init(void)
{
	char *u, *p;

	socks5_auth_methods[SOCKS5_AUTH_NOAUTH]   = socks5_auth_noauth;
	socks5_auth_methods[SOCKS5_AUTH_USERNAME] = socks5_auth_username;

	socks5_auth_type = SOCKS5_AUTH_NOAUTH;

	if ((u = getenv(PROXY_USER)) && (p = getenv(PROXY_PASS))) {
		socks5_auth_type = SOCKS5_AUTH_USERNAME;
		STRINIT(&socks5_user, u, strlen(u));
		STRINIT(&socks5_pass, p, strlen(p));
	}
}

static void stdxyz_init(void)
{
	int null;

	if (!getenv("DEV_NULL"))
		return;
	if ((null = open(_PATH_DEVNULL, O_RDWR)) < 0)
		return;
	dup2(null, STDIN_FILENO);
	dup2(null, STDOUT_FILENO);
	dup2(null, STDERR_FILENO);
	close(null);	
}

static void sigall(int signo)
{
	int save_errno = errno;
	
	if (signo == SIGCHLD)
		while (waitpid(-1, NULL, WNOHANG) > 0) ;
	else
		loop_quit();
	
	errno = save_errno;
}

static void usage(void)
{
	extern const char *const __progname;
	fprintf(stderr,
		"\n"
		"usage: %s [io_drv] [bind_addr] [bind_port] [authenticator ...]\n"
		"\n"
		"    io_drv    : select, poll"
#ifdef HAVE_EPOLL
		", epoll"
#endif
		"\n"
		"    bind_addr : %s\n"
		"    bind_port : %s\n"
		"\n", __progname, PROXY_ADDR, PROXY_PORT);
	exit(EXIT_FAILURE);
}

static void sigs_init()
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sigfillset(&sa.sa_mask);
	sa.sa_handler = sigall;

	signal(SIGPIPE, SIG_IGN);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGCHLD, &sa, NULL);
}

static void prefork_init()
{
	char *prefork = getenv("PREFORK");
	int i, n;

	if (prefork && (n = atoi(prefork)) > 1) {
		/* main is already started -1 */
		for (i = 0; i < n - 1; i++) {
			pid_t pid = fork();
			if (!pid)
				break;
			WARNX("run worker %d", pid);
		}
	}
}

int main(int argc, char *argv[])
{
	char *addr, *port;
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
	addr = argc > 2 ? argv[2] : PROXY_ADDR;
	port = argc > 3 ? argv[3] : PROXY_PORT;

	if (argc > 4) {
		if (access(argv[4], X_OK) < 0)
			ERRX("%s does not exist or isn't executable", argv[4]);
		socks5_auth_prog = &argv[4];
	}

	sigs_init();

	if ((fd = tcp_listen(addr, port)) < 0)
		ERR("tcp_listen() failed");
	if (fd_nonblock(fd) < 0)
		ERR("fd_nonblock() failed");

	prefork_init();

	if (loop_init(drv) < 0)
		ERRX("loop_init() failed");

	cache_init(&coroutine_cache, COROUTINE_CACHE_INIT_SIZE,
			coroutine_item_alloc, NULL, coroutine_item_free);
	socks5_auth_init();
	stdxyz_init();

	srv = coroutine_create(0, srv_loop, (void *)(intptr_t)fd);
	coroutine_resume(srv);

	loop_run();

	cache_deinit(&coroutine_cache);
	coroutine_destroy(&srv);
	loop_fini();
	close(fd);

	return EXIT_SUCCESS;
}

