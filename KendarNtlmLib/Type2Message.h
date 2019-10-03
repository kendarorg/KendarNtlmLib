#pragma once
struct Type2Message
{
	unsigned char    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	unsigned char    type;            // 0x02
	unsigned char    zero[3];
	short target_name_len;
	short target_name_len1;

	short   target_name_off;         // 0x28
	unsigned char    zero1[2];
	unsigned long   flags;          // 0x8201

	unsigned char    nonce[8];        // nonce
	unsigned char    zero3[8];        //Context
};

struct Type2MessageSecurityBuffer
{
	short sec_buf_len;
	short sec_buf_len1;

	long   sec_buf_off;         // 0x28
	//unsigned char * targetNameData;
	//unsigned long terminator; //0x00000000
};