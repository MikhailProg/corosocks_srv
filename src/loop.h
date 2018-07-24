#ifndef LOOP_H
#define LOOP_H

typedef enum {
	LOOP_RD	 = 0x01,
	LOOP_WR  = 0x02,
	LOOP_ERR = 0x04
} LoopEvent;

typedef enum {
	LOOP_DRV_SELECT,
	LOOP_DRV_POLL,
#ifdef HAVE_EPOLL
	LOOP_DRV_EPOLL,
#endif
	LOOP_DRV_MAX
} LoopDrvType;

#ifdef HAVE_EPOLL
#  define LOOP_DRV_DEFAULT	LOOP_DRV_EPOLL
#else
#  define LOOP_DRV_DEFAULT	LOOP_DRV_POLL
#endif

typedef int Fd;
typedef void (*LoopEventCb)(Fd, LoopEvent, void *);

int		loop_init(LoopDrvType);
int		loop_fd_add(Fd, LoopEvent, LoopEventCb, void *);
int		loop_fd_change(Fd, LoopEvent);
int		loop_fd_del(Fd);
LoopEvent	loop_fd_events(Fd);
void		loop_run(void);
void		loop_quit(void);
void		loop_fini(void);

#endif /* LOOP_H */
