#pragma once
/*
#include <stdio.h>
#include <windows.h>
*/
#include <string>
#include "type3message.h"

extern void lm_create_hash(const char *password, unsigned char result[16]);
extern void nt_create_hash(const char *key,unsigned char hash[16]);
extern void lm_create_response(const unsigned char *nt_lm_hash, const unsigned char *challenge, unsigned char* result);

extern void* zero_malloc(int size);
extern bool cmp(unsigned char* left,unsigned char* right,int len);

extern void nt2_create_response(Type3Message* t3m,unsigned char* nt_hash,unsigned char* result,unsigned char* nonce);