CC=gcc
CFLAGS=-Wall -Os

GITVER=$(shell git log -n1 --pretty --format=%ad --date=format:%Y%m%d.%H%M)
DEFINE=$(shell echo "\#define VERSION \"$(GITVER)\"" > version.h)

$(DEFINE)

raat: main.o push.o pull.o common.o
	$(CC) -o raat main.o push.o pull.o common.o

clean:
	rm -f raat *.o
