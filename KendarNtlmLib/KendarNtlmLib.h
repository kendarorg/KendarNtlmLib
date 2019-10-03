#pragma once
#include "Type1Message.h"
#include "Type2Message.h"
#include "Type3Message.h"

using namespace System;

#define NTLMSSP	("NTLMSSP")

namespace KLib
{
	public ref class KendarNtlmLib
	{
	public:
		KendarNtlmLib(unsigned char* nonce,unsigned char *targetDomain,int tdLen,unsigned char* targetServer,int tsLen);
		~KendarNtlmLib(void);

		void ReadFirstResponse(unsigned char* type2msg,int type2msgLen);
		int PrepareFirstResponse(unsigned char * type1msg,int type1msgLen,unsigned char*type2msg,int type2msgLen);
		int InitializeLastMessage(unsigned char* type3msg,int type3msgLen);
		int ReadUserData(unsigned char type,unsigned char*userData,int userDataLen);
		bool VerifyPassword(unsigned char*expectedPwd,int expectedPwdLen);
	private:
		Type3Message* m_type3message;
		unsigned char *m_nonce;
		unsigned char* m_targetDomain;
		unsigned char* m_targetServer;
		int m_targetDomainLen;
		int m_targetServerLen;

		int RetrieveType2MessageLen(unsigned char* type1msg,int type1msgLen);
		int BuildType2Message(unsigned char* type1msg,int type1msgLen,unsigned char*type2msg,int type2msgLen);
		Type1Message* InitializeType1Message(unsigned char* type1msg,int type1msgLen);
		void FreeType1Message(Type1Message* t1m);
		Type2Message* InitializeType2Message();
		void InitializeType3Message(unsigned char* type3msg,int type3msgLen);
		void FreeType3Message();
	};
}