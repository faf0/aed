CC = gcc
CFLAGS = -g -Wall -pedantic
OBJECTS = aed.o util.o
INCFLAGS = 
LIBS = 

UNAME := $(shell uname)

LDFLAGS = -Wl,-rpath,/usr/local/lib,-lbsd-ctor,-lbsd,-lssl,-lcrypto

all: aed

aed: $(OBJECTS)
	$(CC) -o aed $(OBJECTS) $(LDFLAGS) $(LIBS)

.SUFFIXES:
.SUFFIXES:	.c .o

.c.o :
	$(CC) -o $@ -c $(CFLAGS) $< $(INCFLAGS)

count:
	wc *.c *.h

clean:
	rm -f *.o aed

.PHONY: all
.PHONY: count
.PHONY: clean
