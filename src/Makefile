CFLAGS := -pipe -Wall -Wextra -D_FORTIFY_SOURCE=0
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

coroutine.o: coroutine.c coroutine.h
libcoro.a: libcoro.a(coroutine.o)

passfd.o: passfd.c passfd.h
libpassfd.a: libpassfd.a(passfd.o)

corosocks_srv.o: corosocks_srv.c common.h socks5.h \
		libloop.a libinet.a libcoro.a libpassfd.a
corosocks_srv: LDLIBS  += -lloop -lcoro -linet -lpassfd
corosocks_srv: LDFLAGS += -L.

clean:
	rm -f *.o *.a $(TARGET)

