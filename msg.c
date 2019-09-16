#include "msg.h"

header_t init_msg_header(char_t type, char_t action, int msg_len)
{

	header_t h;
	h.type = type;
	h.action = action;
  	memset(h.len, 0, (MAX_LEN_SIZE + 1) * sizeof(char_t));
  	memcpy(h.len, "00000000", MAX_LEN_SIZE);
    sprintf(h.len, "%08lx", (long unsigned int)msg_len);
	return h;
}


char_t* header_to_str(header_t h)
{
	// char* str = (char*) calloc (10,  sizeof(char));
  	static char_t hstr[MSG_HDR_LEN + 1];
  	memset(hstr, 0, (MSG_HDR_LEN + 1) * sizeof(char_t));
	hstr[0] = h.type;
	hstr[1] = h.action;
	memcpy(hstr+2, h.len, 8);
	return hstr;
}

header_t str_to_header(char_t* str)
{

    header h;
    h.type = str[0];
    h.action = str[1];
    memset(h.len, 0, (MAX_LEN_SIZE + 1) * sizeof(char_t));
    memcpy(h.len, str + 2, MAX_LEN_SIZE);
    return h;
}



char_t* keys_to_str(keys_t keys)
{
	static char_t buf[64+32];

	memset(buf, 0, (64+32) * sizeof(char_t));
	memcpy(buf, keys.key_priv, 32);
	memcpy(buf+32, keys.key_pub, 64);

	return buf;
}


keys_t str_to_keys(char_t* str)
{
	keys_t key_pair;
	unsigned char* tstr = (unsigned char*) str;
	memcpy(key_pair.key_priv, tstr, 32);
	memcpy(key_pair.key_pub, tstr+32, 64);
	return key_pair;
}


void print_hex(char_t* str)
{
	for (int i = 0; i < (int) sizeof(str); i++)
      printf("%x", str[i]);
 	printf("\n");
}


void print_hex_len(char_t* str, int len)
{
	for (int i = 0; i < len; i++)
      printf("%02x", (unsigned char)str[i]);
 	printf("\n");
}




char_t* msg_init(char_t* guard_id)
{

	char_t* msg_body = guard_id;
	int msg_len = strlen(msg_body);
	
	header_t h = init_msg_header(TYPE_INIT, ACTION_TEST, msg_len);
	char_t* t_hdstr = header_to_str(h);
	int buf_size = MSG_HDR_LEN + msg_len + 1;

    char_t* buf = (char_t*) calloc (buf_size, sizeof(char_t));
    memset(buf, 0, buf_size);
    memcpy(buf, t_hdstr, MSG_HDR_LEN);
    memcpy(buf+MSG_HDR_LEN, msg_body, msg_len);

    // printf("%d, %d\n", strlen(buf), buf_size);
    return buf;

}



char_t* msg_basic(char_t type, char_t action, char_t* msg_body, keys_t keys)
{

	int body_len = strlen(msg_body);
	header_t h = init_msg_header(type, action, body_len);
	
	// unsigned char* key_priv = (unsigned char*) keys.key_priv;

    unsigned char hash[SHA256_DIGEST_SIZE] = {0};
    unsigned char sig[64] = {0};

    sha256((const unsigned char *) msg_body, strlen(msg_body), hash);

    const struct uECC_Curve_t* curve = uECC_secp256r1();

    if (!uECC_sign((unsigned char*) keys.key_priv, hash, sizeof(hash), sig, curve)) {
 		 printf("uECC_sign() failed\n");
         exit(EXIT_FAILURE);   	
    }


    char_t* t_hd_str = header_to_str(h);

    int buf_size = MSG_HDR_LEN + MSG_SIG_LEN + body_len + 1;

    char_t* buf = (char_t*) calloc (buf_size,  sizeof(char_t));
    memset(buf, 0, buf_size);

    memcpy(buf, t_hd_str, MSG_HDR_LEN);
    memcpy(buf + MSG_HDR_LEN, msg_body, body_len);
    memcpy(buf + MSG_HDR_LEN + body_len, sig, MSG_SIG_LEN);

	return buf;

}


char* msg_basic_2(char type, char action, char* msg_body, keys_t keys)
{

	int body_len = strlen(msg_body);
	header_t h = init_msg_header(type, action, body_len);
	
	// unsigned char* key_priv = (unsigned char*) keys.key_priv;

    unsigned char hash[SHA256_DIGEST_SIZE] = {0};
    unsigned char sig[64] = {0};

    // sha256((const unsigned char *) msg_body, strlen(msg_body), hash);


    // const struct uECC_Curve_t* curve = uECC_secp256r1();

    // if (!uECC_sign((unsigned char*) keys.key_priv, hash, sizeof(hash), sig, curve)) {
 		 // printf("uECC_sign() failed\n");
    //      exit(EXIT_FAILURE);   	
    // }


    char_t* t_hd_str = header_to_str(h);

    int buf_size = MSG_HDR_LEN + MSG_SIG_LEN + body_len + 1;

    char_t* buf = (char_t*) calloc (buf_size,  sizeof(char_t));
    memset(buf, 0, buf_size);

    memcpy(buf, t_hd_str, MSG_HDR_LEN);
    memcpy(buf + MSG_HDR_LEN, msg_body, body_len);
    memcpy(buf + MSG_HDR_LEN + body_len, hash, MSG_SIG_LEN);

	return buf;

}


msg_t msg_parser(char_t* msg_str)
{

	msg_t msg;
	char hdr_str[MSG_HDR_LEN+1];
	memset(hdr_str, 0, sizeof(hdr_str));
	memcpy(hdr_str, msg_str, MSG_HDR_LEN);

	msg.header = str_to_header(hdr_str);
	int body_len = strtol(msg.header.len, NULL, 16);
	
	msg.body = (char_t*) calloc (body_len+1, sizeof(char_t));
	memset(msg.body, 0, body_len+1);
	memcpy(msg.body, msg_str + MSG_HDR_LEN, body_len);
	
	memset(msg.signature, 0, MSG_SIG_LEN+1);
	memcpy(msg.signature, msg_str + MSG_HDR_LEN + body_len, MSG_SIG_LEN);
	
	return msg;
}

int msg_verfy(msg_t msg, unsigned char* key_pub, const uECC_Curve_t* curve)
{
	int body_len = strtol(msg.header.len, NULL, 16);
	
	unsigned char hash[SHA256_DIGEST_SIZE] = {0};
	
	sha256((const unsigned char *) msg.body, body_len, hash);


	printf("msg_size_get %d, %d, %d\n", body_len, strlen(msg.body), sizeof(hash));
	// print_hex_len(msg.body, body_len);
 	// print_hex_len((char*)prev_key[0].key_pub, 64);
 	
 	
 	// const struct uECC_Curve_t* curve1 = uECC_secp256r1();
 	
	if (!uECC_verify(key_pub, hash, sizeof(hash), (unsigned char*) msg.signature, curve)) {
     	printf("uECC_verify() failed\n");
     	return 0;
    }
    printf("uECC_verify() pass\n");
    return 1;

}
