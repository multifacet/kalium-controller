#include "defs.h"

/* Construct the header field of a message */
header_t init_msg_header(char type, char action, int msg_len);
/* Convert the header of a message to string */
char *header_to_str(header_t h);
/* Construct the header object from a string */
header_t str_to_header(char *str);
/* Convert keys to string */
char *keys_to_str(keys_t keys);
/* Construct the key object from a string */
keys_t str_to_keys(char *str);
/* Print string as hex string, for debugging*/
void print_hex(char *str);
/* Print the first N bytes of string as hex*/
void print_hex_len(char *str, int len);

/* Construct an empty message */
char *msg_init(char *guard_id);
/* Construct an message with input information */
char *msg_basic(char type, char action, char *msg_body);
char *msg_basic2(char type, char action, char *msg_body, keys_t keys);
/* Construct a message object from string */
msg_t msg_parser(char *msg_str);

/* Verify the signature of a message. This function is not used */
int msg_verfy(msg_t msg, unsigned char *key_pub, const uECC_Curve_t *curve);
