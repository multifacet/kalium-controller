
all: guard ctr

CC = g++

CFLAGS = -g -Wall -std=c++11 

INCLUDES = -Irapidjson/include 

LIBS = -lzmq -lpthread  -lm  -static


ZMQOBJ = 
# libzmq/lib/libzmymq.so

guard: hmac.o sha.o guard.o ecc.o msg.o linkedlist.o log.o
	$(CC) $(CFLAGS) guard.o sha.o hmac.o ecc.o msg.o linkedlist.o log.o -o guard $(ZMQOBJ)  $(LIBS) $(INCLUDES)

guard.o: guard.c
	$(CC) $(CFLAGS) -c guard.c -o guard.o $(ZMQOBJ)  $(LIBS) $(INCLUDES)

ctr: hmac.o sha.o ctr.o ecc.o msg.o linkedlist.o log.o
	$(CC) $(CFLAGS)  ctr.o sha.o hmac.o ecc.o  msg.o linkedlist.o  log.o -o ctr $(ZMQOBJ)  $(LIBS) $(INCLUDES)

ctr.o: ctr.c
	$(CC) $(CFLAGS)-c ctr.c -o ctr.o $(ZMQOBJ)  $(LIBS) $(INCLUDES)

msg.o: msg.c msg.h defs.h
	$(CC) $(CFLAGS) -c msg.c -o msg.o $(ZMQOBJ)  $(LIBS) $(INCLUDES)

linkedlist.o: linkedlist.h linkedlist.c
	$(CC) $(CFLAGS) -c linkedlist.c -o linkedlist.o

log.o: log.c log.h 
	$(CC) $(CFLAGS) -c log.c -o log.o

ecc.o: ecc/uECC.c ecc/uECC.h
	$(CC) $(CFLAGS)-c ecc/uECC.c -o ecc.o -Iecc

hmac.o: hmac_sha2.c hmac_sha2.h
	$(CC) $(CFLAGS) -c hmac_sha2.c -o hmac.o

sha.o: sha2.c sha2.h
	$(CC) $(CFLAGS) -c sha2.c -o sha.o

clean:
	-rm -f *.o guard ctr