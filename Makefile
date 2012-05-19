SHELL = /bin/sh

srcdir = .

CC = gcc
CDEBUG = -g
CFLAGS = $(CDEBUG) -I. \
		-I$(srcdir)/include
LDFLAGS = -g

SRCS_C = fd_cache.c log.c pairing_heap.c \
		 main.c

OBJS = $(SRCS_C:.c=.o)

.PHONY: all
all: apiserv

apiserv: ${OBJS}
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

.PHONY: clean
clean:
	rm -rf *.o
