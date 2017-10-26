CC=gcc
CFLAGS=-Wall -Werror -g
CLIBS=-lpcap

analyzer: common capture src/main.c
	$(CC) $(CFLAGS) obj/common.o obj/capture.o src/main.c -o bin/analyzer $(CLIBS)

capture: obj include/capture.h src/capture.c
	$(CC) $(CFLAGS) -c src/capture.c -o obj/capture.o
	
common: obj include/common.h src/common.c
	$(CC) $(CFLAGS) -c src/common.c -o obj/common.o

obj:
	[ -d obj ] || mkdir obj

clean:
	rm -f obj/* bin/*
