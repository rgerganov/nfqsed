all: nfqsed

nfqsed: nfqsed.o
	gcc nfqsed.o -o nfqsed -lnetfilter_queue

nfqsed.o: nfqsed.c
	gcc -Wall -c nfqsed.c

clean:
	rm -f nfqsed.o nfqsed

