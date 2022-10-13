#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <assert.h>

#include "coroutine.h"

/* DETACHED is not a state, it is a flag. */
#define DETACHED	0x01
/* Coroutine states. */
#define RUNNING		0x02
#define	YIELDED		0x04
#define TERMINATED	0x08

#define CORO_BASE(co)	((Coroutine *)co)
#define CORO_IMPL(co)	((CoroutineImpl *)co)

typedef struct CoroutineImpl CoroutineImpl;

struct CoroutineImpl {
	Coroutine	base;
	sigjmp_buf	env;
	void		*sp;
	CoroutineImpl	*callee;
};

static CoroutineImpl coro_main, *current = &coro_main;

static void yield(CoroutineImpl *co, int state, void *resume)
{
	CORO_BASE(co)->resume = resume;
	CORO_BASE(co)->state = state | (CORO_BASE(co)->state & DETACHED);
	
	if (sigsetjmp(current->env, 0) == 0)
		siglongjmp(current->callee->env, 1);
}

void coroutine_yield(void *resume)
{
	assert(current != &coro_main);
	assert(CORO_BASE(current)->state & RUNNING);
	yield(current, YIELDED, resume);
}

static void coroutine_start(CoroutineImpl *co)
{
	if (sigsetjmp(co->env, 0) == 0)
		siglongjmp(co->callee->env, 1);

	for (;;) {
		CORO_BASE(co)->entry(CORO_BASE(co)->opaque);
		yield(co, TERMINATED, NULL);
	}
}

static void sigusr1(int signo)
{
	(void)signo;
	if (sigsetjmp(current->env, 0) == 0)
		return;
	/* We come here not in signal context. */
	coroutine_start(current);
}


void *coroutine_resume(Coroutine *co)
{
	void *resume = co->resume;

	if (co->state & TERMINATED)
		goto out;

	assert(co->state & YIELDED);

	co->state = RUNNING | (co->state & DETACHED);
	CORO_IMPL(co)->callee = current;
	current = CORO_IMPL(co);
	if (sigsetjmp(CORO_IMPL(co)->callee->env, 0) == 0)
		siglongjmp(CORO_IMPL(co)->env, 1);
	resume = co->resume;
	current = CORO_IMPL(co)->callee;
	CORO_IMPL(co)->callee = NULL;

	if ((co->state & TERMINATED) && (co->state & DETACHED))
		coroutine_destroy(&co);
out:
	return resume;
}

Coroutine *
coroutine_create(size_t _stacksz, void (*entry)(void *), void *opaque)
{
	CoroutineImpl *co;
	struct sigaction sa, osa;
	stack_t stack, ostack;
	sigset_t mask, omask;
	size_t stacksz = _stacksz ? _stacksz : CO_STACK_SIZE;

	co = malloc(sizeof(*co));
	if (!co)
		return NULL;

	memset(co, 0, sizeof(*co));
	CORO_BASE(co)->state = YIELDED;
	CORO_BASE(co)->entry = entry;
	CORO_BASE(co)->opaque = opaque;

	co->sp = malloc(stacksz);
	if (!co->sp) {
		free(co);
		return NULL;
	}
	/* Block SIGUSR1, we need it to bootstrap a new coroutine. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigprocmask(SIG_BLOCK, &mask, &omask);

	stack.ss_sp = co->sp;
	stack.ss_size = stacksz;
	stack.ss_flags = 0;
	if (sigaltstack(&stack, &ostack) < 0) {
		free(co->sp);
		free(co);
		sigprocmask(SIG_SETMASK, &omask, NULL);
		return NULL;
	}

	/* Replace SIGUSR1, set the alternative stack for the handler. */	
	memset(&sa, 0, sizeof(sa));
	sigfillset(&sa.sa_mask);
	sa.sa_handler = sigusr1;
	sa.sa_flags = SA_ONSTACK;
	sigaction(SIGUSR1, &sa, &osa);
	
	raise(SIGUSR1);
	sigfillset(&mask);
	sigdelset(&mask, SIGUSR1);
	/* Allow only SIGUSR1 for a while, let the handler save
	 * the execution environment with sigsetjmp in sigusr1(). */
	co->callee = current;
	current = co;
	sigsuspend(&mask);
	current = co->callee;
	co->callee = NULL;
	/* Disable the alternative stack and restore the old stack
	 * if it was active. */	
	sigaltstack(NULL, &stack);
	stack.ss_flags |= SS_DISABLE;
	if (sigaltstack(&stack, NULL) < 0)
		abort();
	if (!(ostack.ss_flags & SS_DISABLE))
		sigaltstack(&ostack, NULL);

	/* Restore the previous handler and the signal mask. */
	sigaction(SIGUSR1, &osa, NULL);
	sigprocmask(SIG_SETMASK, &omask, NULL);

	co->callee = current;
	current = co;
	/* Jump back to sigusr1() but this time not in the signal context. */
	if (sigsetjmp(co->callee->env, 0) == 0)
		siglongjmp(co->env, 1);
	current = co->callee;
	co->callee = NULL;

	return CORO_BASE(co);
}

void coroutine_init(Coroutine *co, void (*entry)(void *), void *opaque)
{
	co->state = YIELDED;
	co->entry = entry;
	co->opaque = opaque;
}

Coroutine *coroutine_self(void)
{
	return CORO_BASE(current);
}

void coroutine_detach(Coroutine *co)
{
	co->state |= DETACHED;
}

void coroutine_on_destroy(Coroutine *co, int (*on_destroy)(Coroutine *))
{
	co->on_destroy = on_destroy;
}

void coroutine_destroy(Coroutine **co)
{
	int release = 1;

	if ((*co)->on_destroy)
		release = (*co)->on_destroy(*co);

	if (release) {
		free(CORO_IMPL((*co))->sp);
		free((*co));
	}
	*co = NULL;
}

const char *coroutine_state(const Coroutine *co)
{
	return co->state & RUNNING ? "running" :
	       co->state & YIELDED ? "yielded" :
	       co->state & TERMINATED ? "terminated" : "unknown";
}

