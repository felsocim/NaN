CC=gcc
CFLAGS=-Wall -Werror -g
CLIBS=-lpcap

analyzer: bin capture src/main.c
	$(CC) $(CFLAGS) obj/common.o obj/useful.o obj/process.o obj/capture.o src/main.c -o bin/analyzer $(CLIBS)

capture: process include/capture.h src/capture.c
	$(CC) $(CFLAGS) -c src/capture.c -o obj/capture.o

process: useful include/process.h src/process.c
	$(CC) $(CFLAGS) -c src/process.c -o obj/process.o

useful: common include/useful.h src/useful.c
	$(CC) $(CFLAGS) -c src/useful.c -o obj/useful.o

common: obj include/common.h src/common.c
	$(CC) $(CFLAGS) -c src/common.c -o obj/common.o

obj:
	test -d obj || mkdir obj

bin:
	test -d bin || mkdir bin

clean:
	rm -f obj/* bin/*
