#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/inotify.h>
#include <limits.h>
#include <errno.h>
#include <sys/time.h>
#include <pthread.h>
#include <zmq.h>
#include <sys/stat.h>
#include <dirent.h>
#include <poll.h>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/stringbuffer.h"
#include "hmac.h"
#include "ecc/uECC.h"
#include "khash.h"
#include "log.h"

#define DEBUG 1

#define CTR_IP "127.0.0.1"
// #define CTR_IP "18.217.190.226"
#define GUARD_IP "127.0.0.1"
#define CTR_PORT 5000
#define GUARD_PORT 6000

#define INOTIFY_EVENT_BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

#define MAX_LEN_SIZE 8
#define MAX_BODY_LEN 4294967295

#define MSG_HDR_LEN 10
#define MSG_SIG_LEN 64

#define MAX_KEY_LEN 16
#define MAX_ID_LEN 16

#define TYPE_TEST 0x01
#define TYPE_POLICY 0x02
#define TYPE_INIT 0x03
#define TYPE_KEY_DIST 0x04
#define TYPE_DISK 0x05
#define TYPE_EVENT 0x06
#define TYPE_DEP_POLICY 0x07
#define TYPE_CHECK_STATUS 0x08
#define TYPE_CHECK_EVENT 0x09
#define TYPE_CHECK_RESP 0x10
#define TYPE_INFO 0x11

#define ACTION_TEST 0x01
#define ACTION_POLICY_ADD 0x02
#define ACTION_POLICY_DEL 0x03
#define ACTION_POLICY_UPDATE 0x04
#define ACTION_POLICY_INIT 0x05
#define ACTION_KEY_DIST 0x06


#define STATE_REQ_RECIVED 0
#define STATE_REQ_VERIFIED 1
#define STATE_PASS 2
#define STATE_FAILED 3

#define EVENT_GET  "GETE"
#define EVENT_SEND  "SEND"
#define EVENT_RESP  "RESP"
#define EVENT_END  "ENDE"
#define EVENT_DONE  "DONE"
#define EVENT_CHECK  "CHCK"
#define EVENT_LEN 4


#define POLICY_TABLE_INIT 0
#define POLICY_TABLE_UPDATE 1
#define POLICY_TABLE_DONE 2
#define POLICY_TABLE_NOOP 3


typedef char char_t;

typedef struct header
{
	char_t type;
	char_t action;
	char_t len[MAX_LEN_SIZE + 1];
	
}header_t;

typedef struct msg
{
	header_t header;
	char_t signature[64];
	char_t* body;
	 
}msg_t;


typedef struct msg_str
{
	char_t header[10];
	char_t signature[64];
	char_t* body;
	 
}msg_str_t;


typedef struct msg_str_buff
{
	int msg_len;
	char* msg_str;
	 
}msg_str_buff_t;

typedef struct keys
{
	unsigned char key_priv[32];
    unsigned char key_pub[64];
}keys_t;


typedef struct node_info
{	
	char_t id[MAX_ID_LEN];
}node_info_t;




// typedef struct graph {
//     Node* begin;
//     Node* nodes[];
// } Graph;

typedef struct event
{	
	char ename[5];
	char* res;

}event_t;



typedef struct para_state_check
{
	void* table;
	char key[MAX_KEY_LEN];
	
}para_state_check_t;


typedef struct path_info
{
  int wd;
  char* name;
} path_info_t;