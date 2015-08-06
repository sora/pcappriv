prog := pcappriv

srcs := $(wildcard *.c)
objs := $(srcs:.c=.o)

CC := gcc
CFLAGS := -O2 -Wall
INC := -I/home/sora/wrk/github.com/wikimedia/analytics-libanon/build/include
LIB := -L/home/sora/wrk/github.com/wikimedia/analytics-libanon/build/lib

all: $(prog)

$(prog): $(objs)
	$(CC) $(CFLAGS) $(INC) $(LIB) -o $@ $^ -lanon

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) $(INC) $(LIB) -c $<

.PHONY: clean
clean:
	$(RM) $(prog) $(objs)
