#define USE_TARGET 
//#define USE_UNKNOWN
#include "stdafx.h"
//#include <stdlib.h>
#include "KendarNtlmLib.h"
#include "Type1Message.h"
#include "Type2Message.h"
#include "Type3Message.h"
#include "NtlmUtils.h"



namespace KLib
{
	KendarNtlmLib::KendarNtlmLib(unsigned char* nonce,unsigned char *targetDomain,int tdLen,unsigned char* targetServer,int tsLen)
	{
		m_targetDomainLen = tdLen;
		m_targetServerLen = tsLen;

		if(m_targetDomainLen>0){
			m_targetDomain = (unsigned char*)malloc(m_targetDomainLen);
			memcpy(m_targetDomain,targetDomain,m_targetDomainLen);
		}

		if(m_targetServerLen>0){
			m_targetServer = (unsigned char*)malloc(m_targetServerLen);
			memcpy(m_targetServer,targetServer,m_targetServerLen);
		}

		m_nonce = (unsigned char*)malloc(8);
		memcpy(m_nonce,nonce,8);
	}

	KendarNtlmLib::~KendarNtlmLib(void)
	{
		free(m_nonce);
		if(m_type3message!=NULL)
		{
			FreeType3Message();
		}
	}

	int KendarNtlmLib::PrepareFirstResponse(unsigned char* type1msg,int type1msgLen,unsigned char*type2msg,int type2msgLen)
	{
		if(type2msgLen==0)
		{
			return RetrieveType2MessageLen(type1msg,type1msgLen);
		}
		return BuildType2Message(type1msg,type1msgLen,type2msg,type2msgLen);
	}

	#define REQUEST_TARGET (0x00000004)
	#define NEGOTIATE_UNICODE (0x00000001)
	#define NEGOTIATE_OEM (0x00000001)
	#define NEGOTIATE_NTLM (0x00000200)
	#define NEGOTIATE_ALWAYS_SIGN (0x00008000)
	#define NEGOTIATE_TARGET_INFO (0x00800000)
	#define TARGET_TYPE_DOMAIN (0x00010000)
	#define TARGET_TYPE_SERVER (0x00020000)
	#define NEGOTIATE_128 (0x20000000)
	#define NEGOTIATE_56 (0x80000000)
	#define UNKNOW_02000000 (0x02000000)

#define TYPE2MSG_SEC_BUFFER_TERMINATOR_LENGTH   (sizeof(long))

	int KendarNtlmLib::RetrieveType2MessageLen(unsigned char* type1msg,int type1msgLen)
	{
		Type1Message* t1m = InitializeType1Message(type1msg,type1msgLen);
		int ret = -1;
		if(cmp(t1m->messageHeader.protocol,(unsigned char*)NTLMSSP,8) && t1m->messageHeader.type==0x01){
			ret = sizeof(Type2Message);
			//t2m sec_buf_off = 0x28

//#ifdef USE_TARGET
			if(t1m->messageHeader.flags & REQUEST_TARGET ){
				if(m_targetDomainLen>0)
					ret += sizeof(Type2MessageSecurityBuffer) + m_targetDomainLen;
				else if(m_targetServerLen>0)
					ret += sizeof(Type2MessageSecurityBuffer) + m_targetServerLen;
			}
//#endif
		}

		FreeType1Message(t1m);
		return ret;
	} 

	void KendarNtlmLib::ReadFirstResponse(unsigned char* type2msg,int type2msgLen)
	{
		Type2Message t2m;
		memcpy(&t2m,type2msg,sizeof(Type2Message));;
		return;
	}

	int KendarNtlmLib::BuildType2Message(unsigned char* type1msg,int type1msgLen,unsigned char*type2msg,int type2msgLen)
	{
		int ret = -1;
		Type1Message* t1m = InitializeType1Message(type1msg,type1msgLen);
		if(cmp(t1m->messageHeader.protocol,(unsigned char*)NTLMSSP,8)&& t1m->messageHeader.type==0x01){
			ret = sizeof(Type2Message);
		}
		if(ret!=-1){
			unsigned char* msbTarget = NULL;
			int msbLen = 0;
			Type2Message* t2m = InitializeType2Message();
			//t2m->flags = 0x02000000;
			/*if(t1m->messageHeader.flags & 0x000000b0){
				t2m->flags = t2m->flags|0x000000b0;
			}*/
			/*if(t1m->messageHeader.flags & 0x80000000){
				t2m->flags = t2m->flags|0x80000000;
			}
			if(t1m->messageHeader.flags & 0x20000000){
				t2m->flags = t2m->flags|0x20000000;
			}*/

			if(t1m->messageHeader.flags & NEGOTIATE_UNICODE) t2m->flags |= NEGOTIATE_UNICODE; 
			if(t1m->messageHeader.flags & NEGOTIATE_NTLM) t2m->flags |= NEGOTIATE_NTLM; 
			t2m->flags |= NEGOTIATE_ALWAYS_SIGN;

//#ifdef USE_UNKNOWN
			/*if(t1m->messageHeader.flags & UNKNOW_02000000){
				t2m->flags |= UNKNOW_02000000;
			}*/
//#endif
			//First without target info data
			if(t1m->messageHeader.flags & REQUEST_TARGET){
				t2m->flags |= REQUEST_TARGET;
				//Initialize securityBuffer
				
				if(m_targetDomainLen>0){
					t2m->flags |= TARGET_TYPE_DOMAIN;
					msbLen = m_targetDomainLen;
					msbTarget = m_targetDomain;
				}else if(m_targetServerLen>0){
					t2m->flags |= TARGET_TYPE_SERVER;
					msbLen = m_targetServerLen;
					msbTarget = m_targetServer;
				}
				if(0!=msbLen){
					t2m->target_name_len = msbLen;
					t2m->target_name_len1 = t2m->target_name_len;
					unsigned char* buf = type2msg + sizeof(Type2Message);
					memcpy(buf,msbTarget,msbLen);
				}
			}
 
			memcpy(type2msg,(void*)t2m,sizeof(Type2Message));

			free(t2m);
		}
		FreeType1Message(t1m);
		return ret;
	}

	Type1Message* KendarNtlmLib::InitializeType1Message(unsigned char* type1msg,int type1msgLen)
	{
		Type1Message*  t1m = (Type1Message*)zero_malloc(sizeof(Type1Message));
		memcpy(&t1m->messageHeader,type1msg,sizeof(Type1Message));
	
		t1m->host = (unsigned char*)zero_malloc(t1m->messageHeader.host_len * sizeof(unsigned char));
		t1m->dom = (unsigned char*)zero_malloc(t1m->messageHeader.dom_len*sizeof(unsigned char));

		memcpy(t1m->host,&type1msg[t1m->messageHeader.host_off],t1m->messageHeader.host_len);
		memcpy(t1m->dom,&type1msg[t1m->messageHeader.dom_off],t1m->messageHeader.dom_len);
		return t1m;
	}

	Type2Message* KendarNtlmLib::InitializeType2Message()
	{
		Type2Message*  t2m = (Type2Message*)zero_malloc(sizeof(Type2Message));
		memcpy(t2m->protocol,(unsigned char*) NTLMSSP, 8);
		t2m->type=2;
		t2m->target_name_len = 0x28;
		t2m->target_name_len1=t2m->target_name_len;
		t2m->flags= 0x00000000 ;
		memcpy(t2m->nonce,m_nonce,8);
		return t2m;
	}

	void KendarNtlmLib::FreeType1Message(Type1Message* t1m)
	{
		free(t1m->host);
		free(t1m->dom);
		free(t1m);
	}


	int KendarNtlmLib::InitializeLastMessage(unsigned char* type3msg,int type3msgLen)
	{
		InitializeType3Message(type3msg,type3msgLen);
		return -1;
	}

	int KendarNtlmLib::ReadUserData(unsigned char type,unsigned char*userData,int userDataLen)
	{
		switch(type){
		case ('U'):
			{
				if(userDataLen<=0){
					return m_type3message->messageHeader.user_len;
				}
				memcpy(userData,m_type3message->user,m_type3message->messageHeader.user_len);
				return m_type3message->messageHeader.user_len;
			}
			break;
		case ('H'):
			{
				if(userDataLen<=0){
					return m_type3message->messageHeader.host_len;
				}
				memcpy(userData,m_type3message->host,m_type3message->messageHeader.host_len);
				return m_type3message->messageHeader.host_len;
			}
			break;
		case ('D'):
			{
				if(userDataLen<=0){
					return m_type3message->messageHeader.dom_len;
				}
				memcpy(userData,m_type3message->dom,m_type3message->messageHeader.dom_len);
				return m_type3message->messageHeader.dom_len;
			}
			break;
		}
		return -1;
	}

	void KendarNtlmLib::InitializeType3Message(unsigned char* type3msg,int type3msgLen)
	{
		Type3Message*  t3m = (Type3Message*)zero_malloc(sizeof(Type3Message));
		m_type3message = t3m;
		memcpy(&t3m->messageHeader,type3msg,sizeof(Type3Message));
	
	
		t3m->lm_resp = (unsigned char*)zero_malloc(t3m->messageHeader.lm_resp_len * sizeof(unsigned char));
		memcpy(t3m->lm_resp,&type3msg[t3m->messageHeader.lm_resp_off],t3m->messageHeader.lm_resp_len);
	
		t3m->nt_resp = (unsigned char*)zero_malloc(t3m->messageHeader.nt_resp_len * sizeof(unsigned char));
		memcpy(t3m->nt_resp,&type3msg[t3m->messageHeader.nt_resp_off],t3m->messageHeader.nt_resp_len);

		t3m->host = (unsigned char*)zero_malloc(t3m->messageHeader.host_len * sizeof(unsigned char));
		t3m->dom = (unsigned char*)zero_malloc(t3m->messageHeader.dom_len * sizeof(unsigned char));

		memcpy(t3m->host,&type3msg[t3m->messageHeader.host_off],t3m->messageHeader.host_len);
		memcpy(t3m->dom,&type3msg[t3m->messageHeader.dom_off],t3m->messageHeader.dom_len);
	
		t3m->user = (unsigned char*)zero_malloc(t3m->messageHeader.user_len * sizeof(unsigned char));
		memcpy(t3m->user,&type3msg[t3m->messageHeader.user_off],t3m->messageHeader.user_len);
		if(!cmp(t3m->messageHeader.protocol,(unsigned char*)NTLMSSP,8)&& !t3m->messageHeader.type==0x03){
			FreeType3Message();
		}
	}

	void KendarNtlmLib::FreeType3Message()
	{	
		free(m_type3message->host);
		free(m_type3message->dom);
		free(m_type3message->user);
		free(m_type3message->nt_resp);
		free(m_type3message->lm_resp);
		free(m_type3message);
		m_type3message = NULL;
	}

	unsigned char reverse(unsigned char old_val)
	{
		 unsigned char new_val = 0;
		 if (old_val & 0x01) new_val |= 0x80;
		 if (old_val & 0x02) new_val |= 0x40;
		 if (old_val & 0x04) new_val |= 0x20;
		 if (old_val & 0x08) new_val |= 0x10;
		 if (old_val & 0x10) new_val |= 0x08;
		 if (old_val & 0x20) new_val |= 0x04;
		 if (old_val & 0x40) new_val |= 0x02;
		 if (old_val & 0x80) new_val |= 0x01;
		 return(new_val);
	} 

	int swap(int x)
	{
		x = (x & 0x0000FFFF) << 16 | (x & 0xFFFF0000) >> 16;
		x = (x & 0x00FF00FF) << 8 | (x & 0xFF00FF00) >> 8;  
		return x;
	}


	bool KendarNtlmLib::VerifyPassword(unsigned char*expectedPwd,int expectedPwdLen)
	{
		unsigned char nonce[8];
		memcpy(nonce,m_nonce,8);
	
		unsigned char lm_hpw[21];
		unsigned char nt_hpw[21];

		lm_create_hash((const char*)expectedPwd, lm_hpw);
		nt_create_hash((const char*)expectedPwd, nt_hpw);

		unsigned char lm_resp[24];
		unsigned char nt_resp[24];
		lm_create_response(lm_hpw, nonce, lm_resp);
		lm_create_response(nt_hpw, nonce, nt_resp);

		unsigned char sample[128];
		unsigned long sample2[128];
		memcpy(sample,m_type3message->nt_resp,m_type3message->messageHeader.nt_resp_len);
		memcpy(sample2,m_type3message->nt_resp,m_type3message->messageHeader.nt_resp_len);

		bool okNt = false;
		bool okLm = false;
		bool okNtV2 = false;
		bool okLmV2 = false;
		if(m_type3message->messageHeader.nt_resp_len>0x18)
		{
			unsigned char nt_md5_hpw[16];
			memset(nt_md5_hpw,0,16);
			nt2_create_response(m_type3message,nt_hpw,&nt_md5_hpw[0],m_nonce);
			okNtV2 =  cmp((unsigned char*)nt_md5_hpw,(unsigned char*)m_type3message->nt_resp,16);

		}else if(m_type3message->messageHeader.nt_resp_len==0x18){
			okNt = cmp((unsigned char*)nt_resp,(unsigned char*)m_type3message->nt_resp,
						m_type3message->messageHeader.nt_resp_len);
		}

		okLm = cmp((unsigned char*)lm_resp,(unsigned char*)m_type3message->lm_resp,
			m_type3message->messageHeader.lm_resp_len);

		//okLmV2 = cmp((unsigned char*)lm_resp,(unsigned char*)m_type3message->lm_resp,
		//	m_type3message->messageHeader.lm_resp_len);
		
		return okNtV2 || okLmV2 || (okNt && okLm);

	}
}