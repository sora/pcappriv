CC=gcc
CXX=g++
CFLAGS=-g -Wall -O2 -I..
CXXFLAGS=$(CFLAGS)
PROGS=cache

all:$(PROGS)

clean:
		rm -fr $(PROGS) *.dSYM a.out *.o

cache: cache.c cache.h khash.h
		$(CC) $(CFLAGS) -o $@ cache.c

