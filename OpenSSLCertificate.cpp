#include "StdAfx.h"
#include "OpenSSLCertificate.h"

COpenSSLCertificate::COpenSSLCertificate(void)
{
}

COpenSSLCertificate::~COpenSSLCertificate(void)
{
}

ULONG COpenSSLCertificate::_DecodeX509Cert(LPBYTE lpCertData, ULONG ulDataLen)  
{     
	if (!lpCertData || ulDataLen == 0)  
	{  
		return CERT_ERR_INVALIDPARAM;  
	}  

	m_pX509 = d2i_X509(NULL, (unsigned char const **)&lpCertData, ulDataLen);  
	if (m_pX509 == NULL)   
	{  
		return CERT_ERR_FAILED;  
	} 

	return CERT_ERR_OK;  
}  

ULONG COpenSSLCertificate::_DecodeP7bCert(LPBYTE lpCertData, ULONG ulDataLen)  
{  
	ULONG ulRes = CERT_ERR_OK;  
	ULONG ulFlag = CRYPT_FIRST;  
	ULONG ulContainerNameLen = 512;  
	CHAR csContainerName[512] = {0};  
	BOOL bFoundContainer = FALSE;  

	if (!lpCertData || ulDataLen == 0)  
	{  
		return CERT_ERR_INVALIDPARAM;  
	}  

	// 由证书链创建一个证书库  
	HCERTSTORE hCertStore = NULL;  
	CRYPT_DATA_BLOB dataBlob = {ulDataLen, lpCertData};  
	hCertStore = CertOpenStore(CERT_STORE_PROV_PKCS7, GLOBAL_ENCODING_TYPE, NULL, 0, &dataBlob);  
	if (NULL == hCertStore)  
	{  
		ulRes = GetLastError();  
		return ulRes;  
	}  

	// 释放之前的证书内容  
	if (m_pCertContext)  
	{  
		CertFreeCertificateContext(m_pCertContext);  
		m_pCertContext = NULL;  
	}  

	// 得到第一个证书内容  
	m_pCertContext = CertEnumCertificatesInStore(hCertStore, m_pCertContext);  
	if (NULL == m_pCertContext)  
	{  
		ulRes = GetLastError();  
		goto CLOSE_STORE;  
	}             

	// 关闭证书库  
CLOSE_STORE:  
	if (hCertStore)  
	{  
		CertCloseStore(hCertStore, 0);  
		hCertStore = NULL;  
	}  

	return ulRes;  
}  

ULONG COpenSSLCertificate::_DecodePfxCert(LPBYTE lpCertData, ULONG ulDataLen, LPSTR lpscPassword)  
{  
	ULONG ulRes = 0;  
	HCERTSTORE hCertStore = NULL;  
	PCCERT_CONTEXT  pCertContext = NULL;    

	USES_CONVERSION;  

	if (!lpCertData || ulDataLen == 0)  
	{  
		return CERT_ERR_INVALIDPARAM;  
	}  

	// 创建证书库  
	CRYPT_DATA_BLOB dataBlob = {ulDataLen, lpCertData};  
	hCertStore = PFXImportCertStore(&dataBlob, lpscPassword ? A2W(lpscPassword) : NULL, CRYPT_EXPORTABLE);  
	if (NULL == hCertStore)  
	{  
		hCertStore = PFXImportCertStore(&dataBlob, L"", CRYPT_EXPORTABLE);  
	}  
	if (NULL == hCertStore)  
	{  
		ulRes = GetLastError();  
		return ulRes;  
	}  

	// 枚举证书，只处理第一个证书  
	while(pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext))  
	{         
		if (pCertContext->pbCertEncoded && pCertContext->cbCertEncoded > 0)  
		{  
			m_pCertContext = CertDuplicateCertificateContext(pCertContext);  
			break;  
		}  
	}  

	// 关闭证书库  
	CertCloseStore(hCertStore, 0);  
	hCertStore = NULL;  

	return ulRes;  
}  