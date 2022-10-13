CFLAGS := -pipe -Wall -Wextra
OS     := $(shell uname -s)
TARGET := corosocks_srv

.PHONY: all clean

ifdef M32
  CFLAGS  += -m32
  LDFLAGS += -m32
endif

ifdef DEBUG
  CFLAGS += -O0 -g
else
  CFLAGS += -O2 -DNDEBUG
  ifneq "$(OS)" "Darwin"
    LDFLAGS += -s
  endif
endif

ifeq "$(OS)" "Linux"
  CFLAGS += -DHAVE_EPOLL
endif

all: $(TARGET)

loop.o: loop.c loop.h
libloop.a: libloop.a(loop.o)

inet.o: inet.c inet.h
libinet.a: libinet.a(inet.o)

coroutine.o: CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -Wno-clobbered
coroutine.o: coroutine.c coroutine.h
libcoro.a: libcoro.a(coroutine.o)

passfd.o: passfd.c passfd.h
libpassfd.a: libpassfd.a(passfd.o)

cache.o: cache.c cache.h
libcache.a: libcache.a(cache.o)

ifdef SILENT
corosocks_srv.o: CFLAGS += -DSILENT
endif
corosocks_srv.o: corosocks_srv.c common.h socks5.h config.h \
		libloop.a libinet.a libcoro.a libpassfd.a libcache.a

corosocks_srv: LDLIBS  += -lloop -lcoro -linet -lpassfd -lcache
corosocks_srv: LDFLAGS += -L.

clean:
	rm -f *.o *.a $(TARGET)

