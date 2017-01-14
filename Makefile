CC=gcc
CFLAGS=-g -Wall -pedantic -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -I. -std=c11

LDFLAGS=
LIBS=

MAKEDEPEND=${CC} -MM

PROGRAM=testdns

OBJS = hash.o socket.o dns.o dnscache.o testdns.o

DEPS:= ${OBJS:%.o=%.d}

all: ${PROGRAM}

${PROGRAM}: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} ${OBJS} ${LIBS} -o $@

clean:
	rm -f ${PROGRAM} ${OBJS} ${DEPS}

${OBJS} ${DEPS} ${PROGRAM} : Makefile

.PHONY : all clean

%.d : %.c
	${MAKEDEPEND} ${CFLAGS} $< -MT ${@:%.d=%.o} > $@

%.o : %.c
	${CC} ${CFLAGS} -c -o $@ $<

-include ${DEPS}
