#pragma once
struct Type3MessageHeader
{
	unsigned char    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	unsigned char    type;            // 0x03
	unsigned char    zero[3];

	short   lm_resp_len;     // LanManager response length (always 0x18)
	short   lm_resp_len1;     // LanManager response length (always 0x18)
	short   lm_resp_off;     // LanManager response offset
	unsigned char    zero1[2];

	short   nt_resp_len;     // NT response length (always 0x18)
	short   nt_resp_len1;     // NT response length (always 0x18)
	short   nt_resp_off;     // NT response offset
	unsigned char    zero2[2];

	short   dom_len;         // domain string length
	short   dom_len1;         // domain string length
	short   dom_off;         // domain string offset (always 0x40)
	unsigned char    zero3[2];

	short   user_len;        // username string length
	short   user_len1;        // username string length
	short   user_off;        // username string offset
	unsigned char    zero4[2];

	short   host_len;        // host string length
	short   host_len1;        // host string length
	short   host_off;        // host string offset
	unsigned char    zero5[6];

	short   msg_len;         // message length
	unsigned char    zero6[2];

	unsigned long   flags;           // 0x8201
};

struct Type3Message
{
	Type3MessageHeader messageHeader;
	unsigned char    *dom;          // domain string (unicode UTF-16LE)
	unsigned char    *user;         // username string (unicode UTF-16LE)
	unsigned char    *host;         // host string (unicode UTF-16LE)
	unsigned char    *lm_resp;      // LanManager response
	unsigned char    *nt_resp;      // NT response
};