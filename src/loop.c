#include <sys/types.h>
#include <sys/select.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include "loop.h"

typedef void * LoopDrvCtx;
typedef struct LoopDrv LoopDrv;
typedef struct LoopEntry LoopEntry;
typedef struct Event Event;
typedef struct Array Array;

struct LoopEntry {
	Fd		fd;
	LoopEvent	events;
	LoopEventCb	f;
	void		*opaque;
	int		active;		
};

struct Event {
	int		entry;		/* point to LoopEntry */
	LoopEvent	events;
};

struct LoopDrv {
	void		*(*init)(void);
	void		 (*set)(LoopDrvCtx *, Fd, LoopEvent);
	void		 (*del)(LoopDrvCtx *, Fd);
	int		 (*run)(LoopDrvCtx *, void (*notify)(Fd, LoopEvent));
	void		 (*fini)(LoopDrvCtx *);
};

struct Array {
	int		len;
	int		cap;
	size_t		elemsz;
	void		(*init)(void *);
	void		*p[0];
};

#define ARRAY(type) \
struct { \
	Array		common; \
	type		*v; \
}

#define ARRAY_INIT(type, init) \
	{ { 0, 0, sizeof(type), init, {} }, NULL }
#define array_reset(a)		((a)->common.len = 0)
#define array_len(a)		((a)->common.len)
#define array_release(a)	do_release(&(a)->common)
#define array_get(a, i)		((a)->v[(i)])
#define array_push(a, x)	array_put((a), (a)->common.len, (x))
#define array_put(a, i, x)	\
do { \
	do_len_ensure(&(a)->common, (i)); \
	(a)->v[(i)] = (x); \
	(a)->common.len = (i)+1 > (a)->common.len ? (i)+1 : (a)->common.len; \
} while (0)

static void do_release(Array *a)
{
	free(a->p[0]);
	return;	
}

static void do_len_ensure(Array *a, int n)
{
	unsigned char *p, *q;
	void *v;
	int cap;

	if (n < a->cap)
		return;

	cap = a->cap ? a->cap : 8;
	do {
		cap <<= 1;
	} while (n >= cap);

	v = realloc(a->p[0], cap * a->elemsz);

	if (a->init) {
		p = (unsigned char *)v + a->cap * a->elemsz;
		q = p + (cap - a->cap) * a->elemsz;
		while (p < q) {
			a->init(p);
			p += a->elemsz;
		}
	}

	a->p[0] = v;
	a->cap  = cap;
}

static void fd2id_init(void *);
static void ent_init(void *);

static LoopDrv		*loopdrv;
static LoopDrvCtx	*loopdrvctx;
static ARRAY(int)	fd2id		= ARRAY_INIT(int, fd2id_init);
static ARRAY(LoopEntry)	loopents	= ARRAY_INIT(LoopEntry, ent_init);
static ARRAY(Event)	event		= ARRAY_INIT(Event, NULL);
static int		quit;

typedef struct SelectCtx SelectCtx;

struct SelectCtx {
	size_t		setsz;
	fd_set		*ird, *iwr;
	fd_set		*ord, *owr;
	Fd		fdmax;
};

#define SETSZ(n) (size_t)((((n) + NFDBITS - 1) / NFDBITS) * sizeof(fd_mask))

static void *select_init(void)
{
	SelectCtx *ctx = malloc(sizeof(SelectCtx));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(SelectCtx));
	ctx->fdmax = -1;
	return ctx;
}

static void select_grow(SelectCtx *ctx)
{
	size_t setsz, n;

	setsz = ctx->setsz ? ctx->setsz : 1;
	do {
		setsz <<= 1;
 	} while (SETSZ(ctx->fdmax+1) > setsz);

	ctx->ird = realloc(ctx->ird, setsz);
	ctx->iwr = realloc(ctx->iwr, setsz);
	ctx->ord = realloc(ctx->ord, setsz);
	ctx->owr = realloc(ctx->owr, setsz);

	n = setsz - ctx->setsz;
	memset((unsigned char *)ctx->ird + ctx->setsz, 0, n);
	memset((unsigned char *)ctx->iwr + ctx->setsz, 0, n);
	ctx->setsz = setsz;
}

static void select_set(LoopDrvCtx *c, Fd fd, LoopEvent events)
{
	SelectCtx *ctx = (SelectCtx *)c;

	assert(events);
	ctx->fdmax = fd > ctx->fdmax ? fd : ctx->fdmax;
	if (SETSZ(ctx->fdmax+1) > ctx->setsz)
		select_grow(ctx);

	if (events & LOOP_RD)
		FD_SET(fd, ctx->ird);
	else
		FD_CLR(fd, ctx->ird);
	if (events & LOOP_WR)
		FD_SET(fd, ctx->iwr);
	else
		FD_CLR(fd, ctx->iwr);
}

static void select_del(LoopDrvCtx *c, Fd fd)
{
	SelectCtx *ctx = (SelectCtx *)c;
	assert(fd <= ctx->fdmax);
	FD_CLR(fd, ctx->ird);
	FD_CLR(fd, ctx->iwr);
}

static int select_run(LoopDrvCtx *c, void (*notify)(Fd, LoopEvent))
{
	SelectCtx *ctx = (SelectCtx *)c;
	LoopEvent events;
	int rc;
	Fd i;

	memcpy(ctx->ord, ctx->ird, ctx->setsz);
	memcpy(ctx->owr, ctx->iwr, ctx->setsz);
	
	if ((rc = select(ctx->fdmax+1, ctx->ord, ctx->owr, NULL, NULL)) < 0)
		return rc;
	else if (!rc)
		return 0;

	for (i = 0; i <= ctx->fdmax; i++) {
		events = 0;
		if (FD_ISSET(i, ctx->ord))
			events |= LOOP_RD;
		if (FD_ISSET(i, ctx->owr))
			events |= LOOP_WR;
		if (events)
			notify(i, events);
	}

	return 0;
}

static void select_fini(LoopDrvCtx *c)
{
	SelectCtx *ctx = (SelectCtx *)c;
	free(ctx->ird);
	free(ctx->iwr);
	free(ctx->ord);
	free(ctx->owr);
	free(ctx);
}

typedef struct pollfd PollFd;
typedef struct PollCtx PollCtx;

struct PollCtx {
	ARRAY(PollFd)	set;
	ARRAY(int)	fd2set;
};

static void int_init(void *n)
{
	*((int *)n) = -1;
}

static void *poll_init(void)
{
	PollCtx templ = {
		ARRAY_INIT(PollFd, NULL),
		ARRAY_INIT(int, int_init)
	}, *ctx = malloc(sizeof(PollCtx));

	if (!ctx)
		return NULL;
	memcpy(ctx, &templ, sizeof(PollCtx));

	return ctx;
}

static void poll_set(LoopDrvCtx *c, Fd fd, LoopEvent events)
{
	PollCtx *ctx = (PollCtx *)c;
	PollFd *p, fds = { fd, 0, 0 };
	int n;

	assert(events);
	/* Extend index array if fd is new. */
	if (fd >= array_len(&ctx->fd2set))
		array_put(&ctx->fd2set, fd, -1);

	n = array_get(&ctx->fd2set, fd);
	if (n == -1) {
		/* Create a new PollFd entry and link index. */
		n = array_len(&ctx->set);
		array_push(&ctx->set, fds);
		array_put(&ctx->fd2set, fd, n);
	}

	p = &array_get(&ctx->set, n);
	p->events  = (events & LOOP_RD) ? POLLIN  : 0;
	p->events |= (events & LOOP_WR) ? POLLOUT : 0;
}

static void poll_del(LoopDrvCtx *c, Fd fd)
{
	PollCtx *ctx = (PollCtx *)c;
	int n, last;

	assert(fd < array_len(&ctx->fd2set));
	n = array_get(&ctx->fd2set, fd);
	/* Fd already is not inside the backend. */
	if (n == -1)
		return;

	array_put(&ctx->fd2set, fd, -1);

	last = array_len(&ctx->set)-1;
	if (n != last) {
		array_put(&ctx->set, n, array_get(&ctx->set, last));
		array_put(&ctx->fd2set, array_get(&ctx->set, n).fd, n);
	}
	--array_len(&ctx->set);
	//printf("                    POLL %u\n", array_len(&ctx->set));
}

static int poll_run(LoopDrvCtx *c, void (*notify)(Fd, LoopEvent))
{
	PollCtx *ctx = (PollCtx *)c;
	PollFd *fds;
	nfds_t nfds;
	LoopEvent events;
	int rc, revents;
	size_t i;

	fds  = &array_get(&ctx->set, 0);
	nfds = array_len(&ctx->set);

	if ((rc = poll(fds, nfds, -1)) < 0)
		return rc;

	for (i = 0; rc && i < nfds; i++) {
		events = 0;
		revents = fds[i].revents;
		if (revents & (POLLERR | POLLNVAL))
			events |= LOOP_ERR;
		if (revents & (POLLIN | POLLHUP | POLLPRI))
			events |= LOOP_RD;
		if (revents & POLLOUT)
			events |= LOOP_WR;
		if (revents)
			--rc;
		if (events)
			notify(fds[i].fd, events);
	}

	return 0;
}

static void poll_fini(LoopDrvCtx *c)
{
	PollCtx *ctx = (PollCtx *)c;
	array_release(&ctx->set);
	array_release(&ctx->fd2set);
	free(ctx);
}

#ifdef HAVE_EPOLL
#include <sys/epoll.h>

typedef struct epoll_event EPollEvent;
typedef struct EPollCtx EPollCtx;

struct EPollCtx {
	int			efd;
	ARRAY(EPollEvent)	events;
	ARRAY(char)		index;
};

static void char_init(void *c)
{
	*(char *)c = -1;
}

static void *epoll_init(void)
{
	EPollCtx templ = {
		-1,	
		ARRAY_INIT(EPollEvent, NULL),
		ARRAY_INIT(char, char_init)
	}, *ctx = malloc(sizeof(EPollCtx));

	if (!ctx)
		return NULL;
	if ((templ.efd = epoll_create(100)) < 0) {
		free(ctx);
		return NULL;
	}
	memcpy(ctx, &templ, sizeof(EPollCtx));
	return ctx;
}

static void epoll_set(LoopDrvCtx *c, Fd fd, LoopEvent events)
{
	EPollCtx *ctx = (EPollCtx *)c;
	EPollEvent e = { 0 };
	int n, op, rc;

	assert(events);
	/* Extend index array if fd is new. */
	if (fd >= array_len(&ctx->index))
		array_put(&ctx->index, fd, -1);

	n  = array_get(&ctx->index, fd);
	op = EPOLL_CTL_MOD;
	if (n == -1) {
		op = EPOLL_CTL_ADD;
		array_put(&ctx->index, fd, 1);
		array_push(&ctx->events, e);
	}

	e.data.fd = fd;
	e.events  = events & LOOP_RD ? EPOLLIN  : 0;
	e.events |= events & LOOP_WR ? EPOLLOUT : 0;

	rc = epoll_ctl(ctx->efd, op, fd, &e);
	if (rc < 0)
		perror("epoll_ctl");
	assert(rc == 0);
}

static void epoll_del(LoopDrvCtx *c, Fd fd)
{
	EPollCtx *ctx = (EPollCtx *)c;
	EPollEvent e = { 0, { 0 } };
	int n, rc;

	assert(fd < array_len(&ctx->index));
	n = array_get(&ctx->index, fd);
	/* Fd already is not inside the backend. */
	if (n == -1)
		return;
	array_put(&ctx->index, fd, -1);
	--array_len(&ctx->events);
	//printf("                    EPOLL %u\n", array_len(&ctx->events));
	rc = epoll_ctl(ctx->efd, EPOLL_CTL_DEL, fd, &e);
	if (rc < 0)
		perror("epoll_ctl");
	assert(rc == 0);
}

static int epoll_run(LoopDrvCtx *c, void (*notify)(Fd, LoopEvent))
{
	EPollCtx *ctx = (EPollCtx *)c;
	int rc, i, nfds, revents;
	EPollEvent *fds;
	LoopEvent events;

	fds  = &array_get(&ctx->events, 0);
	nfds = array_len(&ctx->events);

	if ((rc = epoll_wait(ctx->efd, fds, nfds, -1)) < 0)
		return rc;

	for (i = 0; i < rc; i++) {
		events = 0;
		revents = fds[i].events;
		if (revents & EPOLLERR)
			events |= LOOP_ERR;
		if (revents & (EPOLLIN | EPOLLHUP | EPOLLPRI))
			events |= LOOP_RD;
#ifdef EPOLLRDHUP
		if (revents & EPOLLRDHUP)
			events |= LOOP_RD;
#endif
		if (revents & EPOLLOUT)
			events |= LOOP_WR;
		notify(fds[i].data.fd, events);
	}

	return 0;
}

static void epoll_fini(LoopDrvCtx *c)
{
	EPollCtx *ctx = (EPollCtx *)c;
	close(ctx->efd);
	array_release(&ctx->events);
	array_release(&ctx->index);
	free(ctx);
}
#endif

#define LOOPDRV(name) \
	{ name##_init, name##_set, name##_del, name##_run, name##_fini }
static LoopDrv loopdrvs[] = {
	LOOPDRV(select),
	LOOPDRV(poll),
#ifdef HAVE_EPOLL
	LOOPDRV(epoll)
#endif
};
#undef LOOPDRV

static void fd2id_init(void *i)
{
	*((int *)i) = -1;
}
static void ent_init(void *e)
{
	((LoopEntry *)e)->fd = -1;
}

int loop_fd_add(Fd fd, LoopEvent events, LoopEventCb f, void *opaque)
{
	LoopEntry entry = { fd, events & (LOOP_RD | LOOP_WR), f, opaque, -1 };
	int id;

	if (fd < 0 || !events)
		return -1;
	/* Fd might be already added. */
	if (fd < array_len(&fd2id) && array_get(&fd2id, fd) != -1)
		return -1;

	id = array_len(&loopents);
	array_put(&loopents, id, entry);
	array_put(&fd2id, fd, id);
	loopdrv->set(loopdrvctx, fd, events);

	return 0;
}

static int fdcheck(Fd fd)
{
	if (fd < 0 || fd >= array_len(&fd2id))
		return 0;
	if (array_get(&fd2id, fd) == -1)
		return 0;
	return 1;
}

LoopEvent loop_fd_events(Fd fd)
{
	int id;

	if (!fdcheck(fd))
		return -1;

	id = array_get(&fd2id, fd);
	return array_get(&loopents, id).events;
}

int loop_fd_change(Fd fd, LoopEvent events)
{
	int id;

	if (!fdcheck(fd))
		return -1;

	events &= (LOOP_RD | LOOP_WR);
	id = array_get(&fd2id, fd);
	/* Don't call driver if events are the same. */
	if (array_get(&loopents, id).events == events)
		return 0;
	array_get(&loopents, id).events = events;
	events ? loopdrv->set(loopdrvctx, fd, events) : loopdrv->del(loopdrvctx, fd);

	return 0;
}

int loop_fd_del(Fd fd)
{
	int id, active, last;

	if (!fdcheck(fd))
		return -1;

	id = array_get(&fd2id, fd);
	/* Invalidate the active event. */
	if ((active = array_get(&loopents, id).active) != -1)
		array_get(&event, active).entry = -1;
	array_put(&fd2id, fd, -1);
	loopdrv->del(loopdrvctx, fd);

	last = array_len(&loopents)-1;
	/* Keep the loop array tightly packed, a[id] <- a[last]. */
	if (id != last) {
		array_put(&loopents, id, array_get(&loopents, last));
		/* If the last event is active, then set a new entry. */
		if ((active = array_get(&loopents, id).active) != -1)
			array_get(&event, active).entry = id;
		array_put(&fd2id, array_get(&loopents, id).fd, id);
	}
	--array_len(&loopents);

	return 0;
}

int loop_init(LoopDrvType set)
{
	if (loopdrv || set >= LOOP_DRV_MAX)
		return -1;
	
	loopdrv = &loopdrvs[set];
	return (loopdrvctx = loopdrv->init()) ? 0 : -1;
}

void loop_fini(void)
{
	if (!loopdrv)
		return;
	loopdrv->fini(loopdrvctx);
	loopdrv = NULL;
	loopdrvctx = NULL;
	array_release(&loopents);
	array_release(&event);
	array_release(&fd2id);
}

static void fdnotify(Fd fd, LoopEvent events)
{
	int id, active;
	Event e;

	id = array_get(&fd2id, fd);
	assert(id != -1);
	if ((active = array_get(&loopents, id).active) != -1) {
		/* Append new events to existing. */
		assert(array_get(&event, active).entry == id);
		array_get(&event, active).events |= events;
	} else {
		e.entry  = id;
		e.events = events;
		array_push(&event, e);
		array_get(&loopents, id).active = array_len(&event)-1;
	}
}

static void loop_spin(void)
{
	LoopEntry *ent;
	LoopEvent e;
	int i;

	if (loopdrv->run(loopdrvctx, fdnotify) < 0)
		return;

	for (i = 0; i < array_len(&event); i++) {
		/* Catch the invalidated event. */
		if (array_get(&event, i).entry == -1)
			continue;
		ent = &array_get(&loopents, array_get(&event, i).entry);
		e = array_get(&event, i).events;
		ent->active = -1;
		ent->f(ent->fd, e, ent->opaque);
	}
	array_reset(&event);
}

void loop_run(void)
{
	while (!quit)
		loop_spin();
}

void loop_quit(void)
{
	quit = 1;
}

