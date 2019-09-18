#include "defs.h"

header_t init_msg_header(char type, char action, int msg_len);
char* header_to_str(header_t h);
header_t str_to_header(char* str);
char* keys_to_str(keys_t keys);
keys_t str_to_keys(char* str);
void print_hex(char* str);
void print_hex_len(char* str, int len);

char_t* msg_init(char* guard_id);
char_t* msg_basic(char type, char action, char* msg_body);
char_t* msg_basic2(char type, char action, char* msg_body, keys_t keys);
msg_t msg_parser(char_t* msg_str);
int msg_verfy(msg_t msg, unsigned char* key_pub, const uECC_Curve_t* curve);
