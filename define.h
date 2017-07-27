#pragma once

#include "../Include/Guomi/SKFAPI.h"


#define CERT_SUBJECT	1	//用户名
#define CERT_UNIQUEID	2	//证书实体唯一标识
#define CERT_DEPT	3	//部门
#define CERT_ISSUE	4	//颁发者DN
#define CERT_DEVICETYPE	8	//证书介质类型
#define CERT_CATYPE	9	//CA类型
#define CERT_KEYTYPE	10	//用户证书密钥类型，（双证或单证）
#define CERT_DEVICENAME	13	//用户证书介质名称
#define CERT_DEVICEPROVIDER	14	//用户证书介质提供者即csp名称
#define CERT_DEVICEAFFIX	15	//用户证书介质附加库
#define CERT_SIGNPATH	16	//用户签名证书路径
#define CERT_EXCHPATH	17	//用户加密证书路径
#define CERT_SIGNPFXPATH	18	//用户签名P12证书路径
#define CERT_EXCHPFXPATH	19	//用户加密P12证书路径
#define CERT_UNIQUEIDOID	22	//用户证书UniqueID的OID


typedef struct READ_CERT_INFO
{
	DEVHANDLE m_hDev; //设备ID
	HAPPLICATION m_hApp;//应用ID
	HCONTAINER  m_hAContainer;//容器ID
	BOOL m_bSignFlag; //TRUE:签名证书，FALSE：加密证书
	BYTE* m_pCert;//证书内容
	ULONG m_ulCertLen;
	void* m_pReadUkey;
	BOOL m_bCloseApp;
	BOOL m_bCloseContainer;
	char m_byPath[500];
	struct READ_CERT_INFO()
	{
		m_hDev = NULL;
		m_hApp = NULL;
		m_hAContainer = NULL;
		m_bSignFlag = TRUE;
		m_pCert = NULL;
		m_ulCertLen = 0;
		m_pReadUkey = NULL;
		m_bCloseApp = FALSE;
		m_bCloseContainer = FALSE;
		memset(m_byPath,0,500);

	}
}ReadCertInfo;

typedef struct REG_WIN_INFO
{
	std::string m_szVID;
	std::string m_szPID;
	std::string m_szName;
	std::string m_szPath;

}RegWinInfo;

typedef struct DEV_NAME_DLL
{
	std::string m_szDevName;//设备名称
	std::string m_szDllFile;//dll全路径
	BOOL m_bOnline;//设备是否在线
	void* m_pReadUkey;
	struct DEV_NAME_DLL()
	{
		m_pReadUkey = NULL;
		m_bOnline = FALSE;
	}

}DevNameDll;