#pragma once




struct MD5Context {
	unsigned int buf[4];
	unsigned int bits[2];
	unsigned char in[64];
};


struct HMACMD5Context {
	struct MD5Context ctx;
	unsigned char k_ipad[65];
	unsigned char k_opad[65];
};


void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
			unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);

/* The following definitions come from lib/hmacmd5.c  */

void hmac_md5_init_rfc2104(unsigned char *key, int key_len,
			struct HMACMD5Context *ctx);
void hmac_md5_init_limK_to_64(const unsigned char *key, int key_len,
			struct HMACMD5Context *ctx);
void hmac_md5_update(const unsigned char *text, int text_len,
			struct HMACMD5Context *ctx);
void hmac_md5_final(unsigned char *digest, struct HMACMD5Context *ctx);
 void hmac_md5(unsigned char key[16], unsigned char *data, int data_len,
			unsigned char *digest);
