#pragma once
struct Type1MessageHeader
{
	unsigned char    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	unsigned char    type;            // 0x01
	unsigned char    zero[3];
	unsigned long   flags;           // 0xb203

	short   dom_len;         // domain string length
	short   dom_len2;         // domain string length
	short   dom_off;         // domain string offset
	unsigned char    zero2[2];

	short   host_len;        // host string length
	short   host_len2;        // host string length
	short   host_off;        // host string offset (always 0x20)
	unsigned char    zero3[2];

};

struct Type1Message
{
	Type1MessageHeader messageHeader;
	unsigned char    *host;         // host string (ASCII)
	unsigned char    *dom;          // domain string (ASCII)
};