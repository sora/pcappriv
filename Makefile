prog := pcappriv

objs := $(prog).o

CC := gcc
CFLAGS := -Wall

all: $(prog)

$(prog): $(objs)
	$(CC) -o $@ $^

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	$(RM) $(prog) $(objs)
