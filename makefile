CC=gcc
CFLAGS=-Wall -Werror -g
CLIBS=-lpcap

analyzer: capture src/main.c
	[ -d bin ] || mkdir bin
	$(CC) $(CFLAGS) obj/capture.o src/main.c -o bin/analyzer $(CLIBS)

capture: include/capture.h src/capture.c
	[ -d obj ] || mkdir obj
	$(CC) $(CFLAGS) -c src/capture.c -o obj/capture.o
	
clean:
	rm -f obj/* bin/*
