#include "defs.h"

header_t init_msg_header(char_t type, char_t action, int msg_len);
char_t* header_to_str(header_t h);
header_t str_to_header(char_t* str);
char_t* keys_to_str(keys_t keys);
keys_t str_to_keys(char_t* str);
void print_hex(char_t* str);
void print_hex_len(char_t* str, int len);

char_t* msg_init(char_t* guard_id);
char_t* msg_basic(char_t type, char_t action, char_t* msg_body, keys_t keys);
char_t* msg_basic_2(char_t type, char_t action, char_t* msg_body, keys_t keys);
msg_t msg_parser(char_t* msg_str);
int msg_verfy(msg_t msg, unsigned char* key_pub, const uECC_Curve_t* curve);