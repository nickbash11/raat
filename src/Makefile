CC=gcc
CFLAGS=-Wall -Os

#GITVER=$(shell git rev-parse HEAD)
GITVER=$(shell git log -n1 --pretty --format=%ad --date=format:%Y%m%d.%H%M)
DEFINE=$(shell echo "\#define VERSION \"$(GITVER)\"" > version.h)

raat: main.o push.o pull.o common.o
	$(DEFINE)
	$(CC) -o raat main.o push.o pull.o common.o

clean:
	rm -f raat *.o
