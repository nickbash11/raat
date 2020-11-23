CC=gcc
CFLAGS=-Wall -O3

raat: main.o push.o pull.o common.o
	$(CC) -o raat main.o push.o pull.o common.o

clean:
	rm -f raat *.o
