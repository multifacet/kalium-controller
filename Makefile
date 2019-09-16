
all: guard ctr

CC = g++

CFLAGS = -g -Wall -std=c++11 

INCLUDES = -Irapidjson/include -Iecc

LIBS = -lzmq -lpthread  -lm  -static

HEADERS = log.h hmac.h sha2.h msg.h defs.h linkedlist.h khash.h

OBJS = log.o hmac.o sha2.o msg.o linkedlist.o

ZMQOBJ = 
# libzmq/lib/libzmymq.so

%.o: %.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS) $(INCLUDES)

guard: $(OBJS) guard.o ecc.o
	$(CC) -o $@ $^ $(CFLAGS) -o guard $(ZMQOBJ) $(LIBS) $(INCLUDES)

guard.o: guard.c 
	$(CC) $(CFLAGS) -c guard.c -o guard.o $(ZMQOBJ) $(LIBS) $(INCLUDES)


ctr: $(OBJS) ctr.o ecc.o
	$(CC) -o $@ $^ $(CFLAGS) -o ctr $(ZMQOBJ) $(LIBS) $(INCLUDES)

ctr.o: ctr.c 
	$(CC) $(CFLAGS) -c ctr.c -o ctr.o $(ZMQOBJ) $(LIBS) $(INCLUDES)

ecc.o: ecc/uECC.c ecc/uECC.h
	$(CC) $(CFLAGS)-c ecc/uECC.c -o ecc.o -Iecc


clean:
	-rm -f *.o guard ctr