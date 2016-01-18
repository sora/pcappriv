CC=gcc
CXX=g++
CFLAGS=-g -Wall -O2 -I..
CXXFLAGS=$(CFLAGS)
PROGS=hash

all:$(PROGS)

clean:
		rm -fr $(PROGS) *.dSYM a.out *.o

hash: hash.c hash.h khash.h
		$(CC) $(CFLAGS) -o $@ hash.c

