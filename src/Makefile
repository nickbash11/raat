CC=gcc
CFLAGS=-Wall -O3

raat: raat_main.o raat_push.o raat_pull.o
	$(CC) -o raat raat_main.o raat_push.o raat_pull.o

clean:
	rm -f raat *.o
