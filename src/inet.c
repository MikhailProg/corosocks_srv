#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "inet.h"

int inet_connect(const char *proto,  const char *host,
		 const char *port, int (*nonblock)(int))
{
	struct addrinfo hint, *result, *iter;
	int fd, rc, dgram, r_errno;

	dgram = strcmp(proto, "udp") == 0 ? 1 :
		strcmp(proto, "tcp") == 0 ? 0 : -1;
	if (dgram < 0) {
		errno = EINVAL;
		return -1;
	}

	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = dgram ? SOCK_DGRAM : SOCK_STREAM;
	hint.ai_family = AF_INET;

	if (getaddrinfo(host, port, &hint, &result)) {
		errno = EINVAL;
		return -1;
	}

	for (iter = result; iter != NULL; iter = iter->ai_next) {
		if ((fd = socket(iter->ai_family, iter->ai_socktype,
				 iter->ai_protocol)) < 0)
			continue;
		if (nonblock && nonblock(fd) < 0) {
			close(fd);
			continue;
		}
		rc = connect(fd, iter->ai_addr, iter->ai_addrlen);
		if (rc == 0 || (rc < 0 && nonblock && errno == EINPROGRESS))
			break;
		close(fd);
	}
	/* Clumsy way to set errno. */
	r_errno = errno;
	if (iter == NULL && !errno)
		r_errno = EINVAL;
	freeaddrinfo(result);
	errno = r_errno;
	return iter == NULL ? -1 : fd;
}

int inet_listen(const char *proto, const char *host, const char *port)
{
	struct addrinfo hint, *result, *iter;
	int fd, reuse = 1, dgram, r_errno;

	dgram = strcmp(proto, "udp") == 0 ? 1 :
		strcmp(proto, "tcp") == 0 ? 0 : -1;
	if (dgram < 0) {
		errno = EINVAL;
		return -1;
	}

	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = dgram ? SOCK_DGRAM : SOCK_STREAM;
	hint.ai_family = AF_INET;
	hint.ai_flags = AI_PASSIVE;

	if (getaddrinfo(host, port, &hint, &result)) {
		errno = EINVAL;
		return -1;
	}

	for (iter = result; iter != NULL; iter = iter->ai_next) {
		if ((fd = socket(iter->ai_family, iter->ai_socktype,
				 iter->ai_protocol)) < 0)
			continue;
		if (!dgram && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
					(void *)&reuse, sizeof(reuse)) < 0)
			goto err;
		if (bind(fd, iter->ai_addr, iter->ai_addrlen) < 0)
			goto err;
		if (!dgram && listen(fd, 4096) < 0)
			goto err;
		break;
err:
		close(fd);
	}
	r_errno = errno;
	if (iter == NULL && !errno)
		r_errno = EINVAL;
	freeaddrinfo(result);
	errno = r_errno;
	return iter == NULL ? -1 : fd;
}

