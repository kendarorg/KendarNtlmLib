#include "stdafx.h"
#include "NtlmUtils.h"
#include "McbDES2.hpp"
#include "md5.h"
#include "type3message.h"

//*************************************************************** 
//Init values
#define INIT_A 0x67452301
#define INIT_B 0xefcdab89
#define INIT_C 0x98badcfe
#define INIT_D 0x10325476
 
#define SQRT_2 0x5a827999
#define SQRT_3 0x6ed9eba1

#define ZEROONE    0x01

static char itoa16[17] = "0123456789ABCDEF";
//*************************************************************** 

void des(const unsigned char password[7], const unsigned char data[8], unsigned char result[8]);

static void nt_create_hash(const char *key,unsigned char hash[21], char* hex_format)
{
    unsigned int nt_buffer[16];
    unsigned int output[4];
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Prepare the string for hash calculation
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    int i = 0;
    int length = strlen(key);
    memset(nt_buffer, 0, 16*4);
    //The length of key need to be <= 27
    for(; i<length/2; i++){
        nt_buffer[i] = key[2 * i] | (key[2 * i + 1] << 16);
    }
    //padding
    if(length % 2 == 1){
        nt_buffer[i] = key[length - 1] | 0x800000;
    }else{
        nt_buffer[i] = 0x80;
    }
    //put the length
    nt_buffer[14] = length << 4;
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // NTLM hash calculation
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    unsigned int a = INIT_A;
    unsigned int b = INIT_B;
    unsigned int c = INIT_C;
    unsigned int d = INIT_D;
 
    /* Round 1 */
    a += (d ^ (b & (c ^ d)))  +  nt_buffer[0]  ;a = (a << 3 ) | (a >> 29);
    d += (c ^ (a & (b ^ c)))  +  nt_buffer[1]  ;d = (d << 7 ) | (d >> 25);
    c += (b ^ (d & (a ^ b)))  +  nt_buffer[2]  ;c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a)))  +  nt_buffer[3]  ;b = (b << 19) | (b >> 13);
 
    a += (d ^ (b & (c ^ d)))  +  nt_buffer[4]  ;a = (a << 3 ) | (a >> 29);
    d += (c ^ (a & (b ^ c)))  +  nt_buffer[5]  ;d = (d << 7 ) | (d >> 25);
    c += (b ^ (d & (a ^ b)))  +  nt_buffer[6]  ;c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a)))  +  nt_buffer[7]  ;b = (b << 19) | (b >> 13);
 
    a += (d ^ (b & (c ^ d)))  +  nt_buffer[8]  ;a = (a << 3 ) | (a >> 29);
    d += (c ^ (a & (b ^ c)))  +  nt_buffer[9]  ;d = (d << 7 ) | (d >> 25);
    c += (b ^ (d & (a ^ b)))  +  nt_buffer[10] ;c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a)))  +  nt_buffer[11] ;b = (b << 19) | (b >> 13);
 
    a += (d ^ (b & (c ^ d)))  +  nt_buffer[12] ;a = (a << 3 ) | (a >> 29);
    d += (c ^ (a & (b ^ c)))  +  nt_buffer[13] ;d = (d << 7 ) | (d >> 25);
    c += (b ^ (d & (a ^ b)))  +  nt_buffer[14] ;c = (c << 11) | (c >> 21);
    b += (a ^ (c & (d ^ a)))  +  nt_buffer[15] ;b = (b << 19) | (b >> 13);
 
    /* Round 2 */
    a += ((b & (c | d)) | (c & d)) + nt_buffer[0] +SQRT_2; a = (a<<3 ) | (a>>29);
    d += ((a & (b | c)) | (b & c)) + nt_buffer[4] +SQRT_2; d = (d<<5 ) | (d>>27);
    c += ((d & (a | b)) | (a & b)) + nt_buffer[8] +SQRT_2; c = (c<<9 ) | (c>>23);
    b += ((c & (d | a)) | (d & a)) + nt_buffer[12]+SQRT_2; b = (b<<13) | (b>>19);
 
    a += ((b & (c | d)) | (c & d)) + nt_buffer[1] +SQRT_2; a = (a<<3 ) | (a>>29);
    d += ((a & (b | c)) | (b & c)) + nt_buffer[5] +SQRT_2; d = (d<<5 ) | (d>>27);
    c += ((d & (a | b)) | (a & b)) + nt_buffer[9] +SQRT_2; c = (c<<9 ) | (c>>23);
    b += ((c & (d | a)) | (d & a)) + nt_buffer[13]+SQRT_2; b = (b<<13) | (b>>19);
 
    a += ((b & (c | d)) | (c & d)) + nt_buffer[2] +SQRT_2; a = (a<<3 ) | (a>>29);
    d += ((a & (b | c)) | (b & c)) + nt_buffer[6] +SQRT_2; d = (d<<5 ) | (d>>27);
    c += ((d & (a | b)) | (a & b)) + nt_buffer[10]+SQRT_2; c = (c<<9 ) | (c>>23);
    b += ((c & (d | a)) | (d & a)) + nt_buffer[14]+SQRT_2; b = (b<<13) | (b>>19);
 
    a += ((b & (c | d)) | (c & d)) + nt_buffer[3] +SQRT_2; a = (a<<3 ) | (a>>29);
    d += ((a & (b | c)) | (b & c)) + nt_buffer[7] +SQRT_2; d = (d<<5 ) | (d>>27);
    c += ((d & (a | b)) | (a & b)) + nt_buffer[11]+SQRT_2; c = (c<<9 ) | (c>>23);
    b += ((c & (d | a)) | (d & a)) + nt_buffer[15]+SQRT_2; b = (b<<13) | (b>>19);
 
    /* Round 3 */
    a += (d ^ c ^ b) + nt_buffer[0]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
    d += (c ^ b ^ a) + nt_buffer[8]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
    c += (b ^ a ^ d) + nt_buffer[4]  +  SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + nt_buffer[12] +  SQRT_3; b = (b << 15) | (b >> 17);
 
    a += (d ^ c ^ b) + nt_buffer[2]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
    d += (c ^ b ^ a) + nt_buffer[10] +  SQRT_3; d = (d << 9 ) | (d >> 23);
    c += (b ^ a ^ d) + nt_buffer[6]  +  SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + nt_buffer[14] +  SQRT_3; b = (b << 15) | (b >> 17);
 
    a += (d ^ c ^ b) + nt_buffer[1]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
    d += (c ^ b ^ a) + nt_buffer[9]  +  SQRT_3; d = (d << 9 ) | (d >> 23);
    c += (b ^ a ^ d) + nt_buffer[5]  +  SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + nt_buffer[13] +  SQRT_3; b = (b << 15) | (b >> 17);
 
    a += (d ^ c ^ b) + nt_buffer[3]  +  SQRT_3; a = (a << 3 ) | (a >> 29);
    d += (c ^ b ^ a) + nt_buffer[11] +  SQRT_3; d = (d << 9 ) | (d >> 23);
    c += (b ^ a ^ d) + nt_buffer[7]  +  SQRT_3; c = (c << 11) | (c >> 21);
    b += (a ^ d ^ c) + nt_buffer[15] +  SQRT_3; b = (b << 15) | (b >> 17);
 
    output[0] = a + INIT_A;
    output[1] = b + INIT_B;
    output[2] = c + INIT_C;
    output[3] = d + INIT_D;
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Convert the hash to hex (for being readable)
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    unsigned char* tmp =(unsigned char*)&output;
    memcpy(hash,tmp,16);
    if(hex_format!=NULL){
        for(i=0; i<4; i++){
            int j = 0;
            unsigned int n = output[i];
            //iterate the bytes of the integer        
            for(; j<4; j++){
                unsigned int convert = n % 256;
                hex_format[i * 8 + j * 2 + 1] = itoa16[convert % 16];
                convert = convert / 16;
                hex_format[i * 8 + j * 2 + 0] = itoa16[convert % 16];
                n = n / 256;
            }    
        }
        //null terminate the string
        hex_format[33] = 0;
    }
}

void nt_create_hash(const char *key,unsigned char hash[21])
{
    memset(hash,0,21);
    nt_create_hash(key,hash,NULL);
}

static bool set_des_parity(unsigned char* pucKey, int nKeyLen)
{
   int cPar;
   char el = ZEROONE;
   for(int i = 0; i < nKeyLen; i++)
   {
      cPar = 0;
      for(int j = 0; j < 8; j++)
      {
         if(pucKey[i] & ( el << j))
            cPar = !cPar;
      }
      if(!cPar){
         pucKey[i] ^= el;
      }
   }
   return true;
}

static void password_to_key(const unsigned char password[7], unsigned char key[8])
{
    /* make room for parity bits */
    key[0] =                        (password[0] >> 0);
    key[1] = ((password[0]) << 7) | (password[1] >> 1);
    key[2] = ((password[1]) << 6) | (password[2] >> 2);
    key[3] = ((password[2]) << 5) | (password[3] >> 3);
    key[4] = ((password[3]) << 4) | (password[4] >> 4);
    key[5] = ((password[4]) << 3) | (password[5] >> 5);
    key[6] = ((password[5]) << 2) | (password[6] >> 6);
    key[7] = ((password[6]) << 1);
    
    set_des_parity(key,8);
}

void lm_create_hash(const char *password, unsigned char result[21])
{
    size_t           i;
    unsigned char          password1[7];
    unsigned char          password2[7];
    unsigned char          kgs[] = "KGS!@#$%";
    unsigned char          hash1[16];
    unsigned char          hash2[16];

    /* Initialize passwords to NULLs. */
    memset(password1, 0, 7);
    memset(password2, 0, 7);

    /* Copy passwords over, convert to uppercase, they're automatically padded with NULLs. */
    for(i = 0; i < 7; i++)
    {
        if(i < strlen(password)){
            password1[i] = toupper(password[i]);
        }
        if(i + 7 < strlen(password)){
            password2[i] = toupper(password[i + 7]);
        }
    }

    /* Do the encryption. */
    des(password1, kgs, hash1);
    des(password2, kgs, hash2);

    /* Copy the result to the return parameter. */
    memset(result,0,21);
    memcpy(result + 0, hash1, 8);
    memcpy(result + 8, hash2, 8);
}

void lm_create_response(const unsigned char *nt_lm_hash, const unsigned char *challenge, unsigned char* result)
{
    size_t i;

    unsigned char password1[7];
    unsigned char password2[7];
    unsigned char password3[7];

    unsigned char hash1[16];
    unsigned char hash2[16];
    unsigned char hash3[16];

    /* Initialize passwords. */
    memset(password1, 0, 7);
    memset(password2, 0, 7);
    memset(password3, 0, 7);

    /* Copy data over. */
    for(i = 0; i < 7; i++){
        password1[i] = nt_lm_hash[i];
        password2[i] = nt_lm_hash[i + 7];
        password3[i] = (i + 14 < 16) ? nt_lm_hash[i + 14] : 0;
    }

    /* do the encryption. */
    des(password1, challenge, hash1);
    des(password2, challenge, hash2);
    des(password3, challenge, hash3); 

    /* Copy the result to the return parameter. */
    memcpy(result + 0,  hash1, 8);
    memcpy(result + 8,  hash2, 8);
    memcpy(result + 16, hash3, 8);
}

static void des(const unsigned char password[7], const unsigned char data[8], unsigned char result[16])
{
    unsigned char tmpResult[48];
    unsigned char key[8];
    memset(tmpResult,0,48);
    password_to_key(password, key);

    McbDES des;
    des.McbSetDES();
    des.McbSetKey1(key);
    des.McbSetCBC(false);
    des.McbSetPadding(false);//must be cb
    unsigned long cbCryptogram = des.McbCalcCryptogramSize(8);
    
    des.McbSetOutputBuffer(tmpResult,cbCryptogram);
    if (des.McbEncrypt(data,8)){
        memcpy(result,tmpResult,16);
    }
    des.McbDecrypt(result,cbCryptogram);
}  

void* zero_malloc(int size)
{
	void* result = malloc(size);
	memset(result,0x0,size);
	return result;
}

bool cmp(unsigned char* left,unsigned char* right,int len)
{
	for(int i=0;i<len;i++){
		if(*left!=*right) return false;
		left++;
		right++;
	}
	return true;
}



static unsigned char *ucase(unsigned char *str, int len)
{
    char *cp = (char *) str;
   
    while (len) {
		if(cp && *cp){
			
			*cp = toupper((int)*cp);
		}
        cp++;
        len--;
    }

    return (str);
}

/* copy src to dst as unicode (in Intel byte-order) */
static void to_unicode(unsigned char *dst, unsigned char *src, int len)
{
    for (; len; len--) {
        *dst++ = *src++;
        *dst++ = 0;
    }
}

#define MD5_DIGEST_LENGTH (16)


unsigned char* from_hex(unsigned char* src1,int* len)
{
	unsigned char* src =(unsigned char*) malloc(strlen((const char*)src1)+1);
	memcpy(src,src1,strlen((const char*)src1)+1);
	ucase(src,strlen((const char*)src));
	*len = strlen((const char*)src)/2;
	unsigned char* dst = (unsigned char*)malloc(*len);
	memset(dst,0,*len);
	unsigned char* res = dst;

    unsigned char *end = dst + (*len);
    unsigned int u;
	

    while (dst < end && sscanf((const char*)src, "%2x", &u) == 1)
    {
        *dst = u;
		dst++;
        src += 2;
    }
	return res;
}

void nt2_create_response(Type3Message* t3m,unsigned char* nt_hash,unsigned char* result,unsigned char* nonce)
{
/*	int tmplen=0;
	int bloblen=0;
	unsigned char* blob =from_hex((unsigned char*)"01010000000000000090d336b734c301ffffff00112233440000000002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d000000000000000000",&bloblen);
	unsigned char* nonc=from_hex((unsigned char*)"0123456789abcdef",&tmplen);

	
	unsigned char*nt_hpw = from_hex((unsigned char*)"cd06ca7c7e10c99b1d33b7485a2ed808",&tmplen);

	unsigned char buf[255];
	unsigned char buf2[255];
	//unsigned char*buf = (unsigned char*)malloc();
	//memcpy(buf,nt_hpw,21);
	memcpy(buf2,"user",4);
	ucase( buf2,4);
	memcpy(buf2+4,"DOMAIN",6);
	
	to_unicode(buf,buf2,4+6);
	memcpy(buf2,buf,254);

	unsigned char ntv2_hash[16];
	//Calculate the ntv2 hash
	HMACMD5Context *ctx = new HMACMD5Context();
	hmac_md5_init_rfc2104(nt_hpw,16,ctx);
	hmac_md5_update(buf2,(4+6)*2,ctx);
	hmac_md5_final(ntv2_hash,ctx);

	memcpy(buf,nonc,8);
	memcpy(buf+8,blob,bloblen);
	
	
	unsigned char ntv2_resp[16];

	ctx = new HMACMD5Context();
	hmac_md5_init_rfc2104(ntv2_hash,16,ctx);
	hmac_md5_update(buf,8+bloblen,ctx);
	hmac_md5_final(result,ctx);*/

	int bloblen = t3m->messageHeader.nt_resp_len-MD5_DIGEST_LENGTH;
	unsigned char* blob =t3m->nt_resp+MD5_DIGEST_LENGTH;
		//(unsigned char*)malloc(t3m->messageHeader.nt_resp_len-MD5_DIGEST_LENGTH);
	//memcpy(blob,t3m->nt_resp+MD5_DIGEST_LENGTH,t3m->messageHeader.nt_resp_len-MD5_DIGEST_LENGTH);
	unsigned char nonc[8];
	memcpy(nonc,nonce,8);

	unsigned char nt_hpw[16];
	memcpy(nt_hpw,nt_hash,16);

	unsigned char buf[0x255];
	unsigned char buf2[0x255];
	//unsigned char*buf = (unsigned char*)malloc();
	//memcpy(buf,nt_hpw,21);
	memcpy(buf2,t3m->user,t3m->messageHeader.user_len);
	ucase( buf2,t3m->messageHeader.user_len);
	memcpy(buf2+t3m->messageHeader.user_len,t3m->dom,t3m->messageHeader.dom_len);
	
	//to_unicode(buf,buf2,4+6);

	unsigned char ntv2_hash[16];
	//Calculate the ntv2 hash
	HMACMD5Context *ctx = new HMACMD5Context();
	hmac_md5_init_rfc2104(nt_hpw,16,ctx);
	hmac_md5_update(buf2,t3m->messageHeader.user_len+t3m->messageHeader.dom_len,ctx);
	hmac_md5_final(ntv2_hash,ctx);

	memcpy(buf,nonc,8);
	memcpy(buf+8,blob,bloblen);
	
	
	unsigned char ntv2_resp[16];

	ctx = new HMACMD5Context();
	hmac_md5_init_rfc2104(ntv2_hash,16,ctx);
	hmac_md5_update(buf,8+bloblen,ctx);
	hmac_md5_final(result,ctx);

/*
#ifdef CASPITA

	unsigned char blob[40];
	blob[0]=0x01;
	blob[1]=0x01;
	blob[2]=0x00;
	blob[3]=0x00;
	blob[4]=0x00;
	blob[5]=0x00;
	blob[6]=0x00;
	blob[7]=0x00;
	blob[8]=0xe3;
	blob[9]=0xa1;
	blob[10]=0x7e;
	blob[11]=0x6c;
	blob[12]=0x26;
	blob[13]=0x00;
	blob[14]=0xce;
	blob[15]=0x01;
	blob[16]=0x91;
	blob[17]=0xf5;
	blob[18]=0x9c;
	blob[19]=0x59;
	blob[20]=0x8f;
	blob[21]=0x8c;
	blob[22]=0x6f;
	blob[23]=0x4d;
	blob[24]=0x00;
	blob[25]=0x00;
	blob[26]=0x00;
	blob[27]=0x00;
	blob[28]=0x02;
	blob[29]=0x00;
	blob[30]=0x00;
	blob[31]=0x00;
	blob[32]=0x00;
	blob[33]=0x00;
	blob[34]=0x00;
	blob[35]=0x00;
	blob[36]=0x00;
	blob[37]=0x00;
	blob[38]=0x00;
	blob[39]=0x00;


	unsigned char nonc[40];
	nonc[0]=0x11;
	nonc[1]=0x22;
	nonc[2]=0x33;
	nonc[3]=0x44;
	nonc[4]=0x55;
	nonc[5]=0x66;
	nonc[6]=0x77;
	nonc[7]=0x88;
	
	unsigned char nt_hpw[21];
	nt_create_hash("hashcat", nt_hpw);

	unsigned char buf[255];
	unsigned char buf2[255];
	//unsigned char*buf = (unsigned char*)malloc();
	//memcpy(buf,nt_hpw,21);
	memcpy(buf2,"user",4);
	memcpy(buf2+4,"DOMAIN",6);
	ucase( buf2,4);
	to_unicode(buf,buf2,4+6);

	unsigned char ntv2_hash[16];
	//Calculate the ntv2 hash
	HMACMD5Context *ctx = new HMACMD5Context();
	hmac_md5_init_rfc2104(nt_hpw,16,ctx);
	hmac_md5_update(buf,(4+6)*2,ctx);
	hmac_md5_final(ntv2_hash,ctx);

	memcpy(buf,nonc,8);
	memcpy(buf+8,blob,40);
	
	
	unsigned char ntv2_resp[16];

	ctx = new HMACMD5Context();
	hmac_md5_init_rfc2104(ntv2_hash,16,ctx);
	hmac_md5_update(buf,(8+40),ctx);
	hmac_md5_final(ntv2_resp,ctx);

	
	

#else
	int start = t3m->messageHeader.user_len+t3m->messageHeader.dom_len;
	unsigned char*buf=(unsigned char*)malloc(2*start);
	//unsigned char*buf = (unsigned char*)malloc();
	//memcpy(buf,nt_hpw,21);
	memcpy(buf,t3m->user,t3m->messageHeader.user_len);
	memcpy(buf+t3m->messageHeader.user_len,t3m->dom,t3m->messageHeader.dom_len);

	ucase( buf,t3m->messageHeader.user_len);
	//to_unicode(buf,buf+start,start);

	unsigned char ntv2_hash[16];
	memset(&ntv2_hash,0,16);

	//Calculate the ntv2 hash
	HMACMD5Context ctx;
	hmac_md5_init_rfc2104(nt_hash,16,&ctx);
	hmac_md5_update(buf,start,&ctx);
	hmac_md5_final(ntv2_hash,&ctx);

	unsigned char*tmpBlob = t3m->nt_resp+MD5_DIGEST_LENGTH;
	//Minus the 
	int bloblen = t3m->messageHeader.nt_resp_len-MD5_DIGEST_LENGTH-16;

	unsigned char* blob = (unsigned char*)malloc(bloblen+16);
	memcpy(blob,tmpBlob,bloblen);
	
	//Calculate the extra hash with the server nonce
	HMACMD5Context ctxSrvNonce;
	hmac_md5_init_rfc2104(ntv2_hash,16,&ctxSrvNonce);
	hmac_md5_update(nonce,8,&ctxSrvNonce);
	hmac_md5_final(result,&ctxSrvNonce);
#endif*/
}