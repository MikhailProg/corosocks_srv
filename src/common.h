#ifndef COMMON_H
#define COMMON_H

#include <errno.h>
#include <err.h>

#define SOFT_ERROR	(errno == EINTR || errno == EAGAIN || \
				errno == EWOULDBLOCK)
#define UNUSED(x)	((x) = (x))

#ifndef SILENT
#  define WARN_DEBUG
#endif

#ifdef WARN_DEBUG
#  define WARN(...)	warn(__VA_ARGS__)
#  define WARNX(...)	warnx(__VA_ARGS__)
#else
#  define WARN(...)	do {} while (0)
#  define WARNX(...)	do {} while (0)
#endif
#define ERR(...)	err(__VA_ARGS__)
#define ERRX(...)	errx(__VA_ARGS__)

#endif /* COMMON_H */
