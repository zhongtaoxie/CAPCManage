#include "StdAfx.h"
#include "CSPCertificate.h"
#include "../Include/Guomi/SKFAPI.h"



CCSPCertificate::CCSPCertificate(void)
{
	m_pCertContext = NULL;
}

CCSPCertificate::~CCSPCertificate(void)
{
}

ULONG CCSPCertificate::_DecodeX509Cert(LPBYTE lpCertData, ULONG ulDataLen)  
{     
	if (!lpCertData || ulDataLen == 0)  
	{  
		return CERT_ERR_INVALIDPARAM;  
	}  

	m_pCertContext = CertCreateCertificateContext(GLOBAL_ENCODING_TYPE, lpCertData, ulDataLen);  
	if (!m_pCertContext)  
	{  
		return GetLastError();  
	}  

	return CERT_ERR_OK;  
}  

ULONG CCSPCertificate::_DecodeP7bCert(LPBYTE lpCertData, ULONG ulDataLen)  
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

ULONG CCSPCertificate::_DecodePfxCert(LPBYTE lpCertData, ULONG ulDataLen, LPSTR lpscPassword)  
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

ULONG CCSPCertificate::get_SN(LPSTR lptcSN,ULONG *pulLen)  
{     
	CHAR scSN[512] = {0};  

	if (!m_pCertContext)  
	{  
		return CERT_ERR_INVILIDCALL;  
	}  
	if (!pulLen)  
	{  
		return CERT_ERR_INVALIDPARAM;  
	}  

	PCRYPT_INTEGER_BLOB pSn = &(m_pCertContext->pCertInfo->SerialNumber);  
	for (int n = (int)(pSn->cbData - 1); n >= 0; n--)  
	{  
		CHAR szHex[5] = {0};  
		sprintf_s(szHex, "%02X", (pSn->pbData)[n]);  
		strcat_s(scSN, 512, szHex);  
	}  

	if (!lptcSN)  
	{  
		*pulLen = strlen(scSN) + 1;  
		return CERT_ERR_OK;  
	}  

	if (*pulLen <= strlen(scSN) + 1)  
	{  
		return CERT_ERR_BUFFER_TOO_SMALL;  
	}  
	strcpy_s(lptcSN, *pulLen, scSN);  
	*pulLen = strlen(scSN);  

	return CERT_ERR_OK;  
}  

ULONG CCSPCertificate::get_KeyHash(ULONG* pulType)  
{     
	if (!m_pCertContext)  
	{  
		return CERT_ERR_INVILIDCALL;  
	}  
	if (!pulType)  
	{  
		return CERT_ERR_INVALIDPARAM;  
	}

	if (_stricmp(m_pCertContext->pCertInfo->SignatureAlgorithm.pszObjId,szOID_RSA_SHA1RSA)==0)
	{
		*pulType = SGD_SHA1;
	}
	else if(_stricmp(m_pCertContext->pCertInfo->SignatureAlgorithm.pszObjId,szOID_RSA_SHA256RSA)==0)
	{
		*pulType = SGD_SHA256;
	}
	else
	{
		*pulType = SGD_SM3;
	}

	return CERT_ERR_OK;  
} 

ULONG CCSPCertificate::get_KeyType(ULONG* pulType)  
{     
	if (!m_pCertContext)  
	{  
		return CERT_ERR_INVILIDCALL;  
	}  
	if (!pulType)  
	{  
		return CERT_ERR_INVALIDPARAM;  
	}  

	PCERT_PUBLIC_KEY_INFO pPubKey = &(m_pCertContext->pCertInfo->SubjectPublicKeyInfo);  
	if (pPubKey)  
	{  
		if (_stricmp(pPubKey->Algorithm.pszObjId, szOID_RSA_RSA) == 0)  
		{  
			*pulType = CERT_KEY_ALG_RSA;  
		}  
		else if (_stricmp(pPubKey->Algorithm.pszObjId, szOID_ECC_PUBLIC_KEY) == 0)  
		{  
			*pulType = CERT_KEY_ALG_ECC;  
		}  
		else   
		{  
			*pulType = 0;  
			return CERT_ERR_ALG_UNKNOWN;  
		}  
	}  
	else  
	{  
		return GetLastError();  
	}  

	return CERT_ERR_OK;  
}  

ULONG CCSPCertificate::get_KeyUsage(ULONG* lpUsage)  
{     
	BYTE btUsage[2] = {0};  

	if (!m_pCertContext)  
	{  
		return CERT_ERR_INVILIDCALL;  
	}  
	if (!lpUsage)  
	{  
		return CERT_ERR_INVALIDPARAM;  
	}  

	if (CertGetIntendedKeyUsage(GLOBAL_ENCODING_TYPE, m_pCertContext->pCertInfo, btUsage, 2))  
	{  
		if (btUsage[0] & CERT_DIGITAL_SIGNATURE_KEY_USAGE)  
		{  
			*lpUsage = CERT_USAGE_SIGN;  
		}  
		else if (btUsage[0] & CERT_DATA_ENCIPHERMENT_KEY_USAGE)  
		{  
			*lpUsage = CERT_USAGE_EXCH;  
		}  
		else  
		{  
			*lpUsage = 0;  
			return CERT_ERR_USAGE_UNKNOWN;  
		}  
	}  
	else  
	{  
		return GetLastError();  
	}  

	return CERT_ERR_OK;  
}  


ULONG CCSPCertificate::get_Issuer(LPSTR lpValue, ULONG *pulLen)  
{  
	ULONG hr = CERT_ERR_OK;  
	ULONG ulIssuerLen = 0;  
	LPTSTR lpszIssuer = NULL;  

	if (!m_pCertContext)  
	{  
		return CERT_ERR_INVILIDCALL;  
	}  
	if (!pulLen)  
	{  
		return CERT_ERR_INVALIDPARAM;  
	}  

	hr = _GetPropertyValue(szOID_COMMON_NAME, CERT_NAME_ISSUER_FLAG, NULL, ulIssuerLen);  
	if (0 != hr || ulIssuerLen == 0)  
	{  
		return hr;  
	}  

	if (!lpValue)  
	{  
		*pulLen = ulIssuerLen;  
		return CERT_ERR_OK;  
	}  
	if (*pulLen <ulIssuerLen)  
	{  
		return CERT_ERR_BUFFER_TOO_SMALL;  
	}  

	hr = _GetPropertyValue(szOID_COMMON_NAME, CERT_NAME_ISSUER_FLAG, lpValue, *pulLen);  
	if (0 != hr)  
	{  
		return hr;  
	}  

	return hr;  
}  

ULONG CCSPCertificate::_GetPropertyValue(LPCSTR szOId, DWORD dwSourceId, LPSTR lpValue, DWORD &dwValLen)  
{  
	if (!m_pCertContext)  
	{  
		return CERT_ERR_INVILIDCALL;  
	}  

	dwValLen = CertGetNameStringA(m_pCertContext, CERT_NAME_ATTR_TYPE,   
		dwSourceId == CERT_NAME_ISSUER_FLAG ? 1 : 0, (void*)szOId, NULL, 0);  
	if (dwValLen <= 1)  
	{  
		return GetLastError();  
	}  

	if (!lpValue)  
	{  
		return CERT_ERR_OK;  
	}  

	dwValLen = CertGetNameStringA(m_pCertContext, CERT_NAME_ATTR_TYPE,   
		dwSourceId == CERT_NAME_ISSUER_FLAG ? 1 : 0, (void*)szOId, lpValue, dwValLen);  
	if (dwValLen <= 1)  
	{  
		return GetLastError();  
	}  

	return CERT_ERR_OK;  
}  

std::string CCSPCertificate::GetCertSubject()
{
	TCHAR Subject[1024] = {0};
	if (!CertNameToStr(X509_ASN_ENCODING,&m_pCertContext->pCertInfo->Subject,
		CERT_X500_NAME_STR,Subject,sizeof(Subject)))
	{
		return "";
	}

	return Subject;
}

ULONG CCSPCertificate::get_SubjectName(LPSTR lpValue, ULONG *pulLen)  
{     
	DWORD dwSubjectLen = 0;  
	CERT_NAME_BLOB certSubject;  

	if (!m_pCertContext)  
	{  
		return CERT_ERR_INVILIDCALL;  
	}  
	if (!pulLen)  
	{  
		return CERT_ERR_INVALIDPARAM;  
	}  

	certSubject = m_pCertContext->pCertInfo->Subject;  
	dwSubjectLen = CertNameToStr(GLOBAL_ENCODING_TYPE, &certSubject, CERT_X500_NAME_STR, NULL, 0);  
	if (dwSubjectLen <= 1)  
	{  
		return E_FAIL;  
	}  

	if (!lpValue)  
	{  
		*pulLen = dwSubjectLen;  
		return CERT_ERR_OK;  
	}  
	if (*pulLen < dwSubjectLen)  
	{  
		return CERT_ERR_BUFFER_TOO_SMALL;  
	}  

	*pulLen = CertNameToStrA(GLOBAL_ENCODING_TYPE, &certSubject, CERT_X500_NAME_STR, lpValue, *pulLen);  
	if (*pulLen <= 1)  
	{  
		return GetLastError();  
	}  

	return CERT_ERR_OK;  
}  

ULONG CCSPCertificate::get_ValidDate(SYSTEMTIME *ptmStart, SYSTEMTIME *ptmEnd)  
{  
	FILETIME ftStart;  
	FILETIME ftEnd;  

	if (!m_pCertContext)  
	{  
		return CERT_ERR_INVILIDCALL;  
	}  

	if (ptmStart)  
	{  
		memcpy(&ftStart, &m_pCertContext->pCertInfo->NotBefore, sizeof(FILETIME));  
		FileTimeToSystemTime(&ftStart, ptmStart);  
	}  
	if (ptmEnd)  
	{  
		memcpy(&ftEnd, &m_pCertContext->pCertInfo->NotAfter, sizeof(FILETIME));  
		FileTimeToSystemTime(&ftEnd, ptmEnd);  
	}  

	return CERT_ERR_OK;  
}  

ULONG CCSPCertificate::gtDecryptData(std::string szData,std::string& szDecryptData)
{
	HCRYPTKEY			m_hSessionKey = NULL;
	HCRYPTPROV			m_hCryptProv = NULL;
	DWORD dwKeyType = 0;  
	BOOL bFreeKeyProv = FALSE;   
	ULONG ulLen  = szData.length();

	BYTE bTemp[1024];
	memset(bTemp,0,1024);
	memcpy(bTemp,szData.c_str(),szData.length());

	int nMiddle = ulLen/2;
	for(int i = 0; i< nMiddle;i++)  
	{  
		BYTE temp = bTemp[i];  
		bTemp[i] = bTemp[ulLen - i - 1];  
		bTemp[ulLen - i - 1] = temp;  
	}

	if(m_hCryptProv)
		CryptReleaseContext(m_hCryptProv, 0);
	if (m_hSessionKey)
		CryptDestroyKey(m_hSessionKey);

	if(!CryptAcquireCertificatePrivateKey(m_pCertContext, 0, 0, &m_hCryptProv, &dwKeyType, &bFreeKeyProv))  //获取证书对应的私钥句柄   
	{
//		throw new CSXException(__FILEW__, __FUNCTIONW__, __LINE__);
		LOG_ERROR("CryptAcquireCertificatePrivateKey is error");
		return -1;
	}
	if(!CryptGetUserKey(m_hCryptProv,AT_KEYEXCHANGE,&m_hSessionKey))//通过句柄获取私钥对象 
	{
		LOG_ERROR("CryptGetUserKey is error");
		return -1;
//		throw new CSXException(__FILEW__, __FUNCTIONW__, __LINE__);
	}
	if(!CryptDecrypt(m_hSessionKey,NULL,TRUE,0,bTemp,&ulLen))//解密,也可以把padding参数换成CRYPT_DECRYPT_RSA_NO_PADDING_CHECK   
	{
		LOG_ERROR("CryptDecrypt is error");
		return -1;
//		throw new CSXException(__FILEW__, __FUNCTIONW__, __LINE__);
	}
	//TODO: by hzl: 解密的数据，没有正确保存。
	//
	szDecryptData = (char*)bTemp;

	return 0;
}

DWORD CCSPCertificate::EnumCerts(BOOL bSig,std::string szCertId)
{
	HCERTSTORE				hCertStore		= NULL; 
	PCCERT_CONTEXT			pCertContext	= NULL;
	TCHAR *					pszStoreName	= TEXT("MY");
	int nRet = -1;

	if ( (hCertStore = CertOpenSystemStore(NULL,pszStoreName)) == NULL)
	{
		return GetLastError();
	}


	while (pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext))
	{
		BYTE pbKeyUsage[2];	
		if (CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,pCertContext->pCertInfo,pbKeyUsage,2))
		{
			if(bSig)
			{
				if ((pbKeyUsage[0] & CERT_DIGITAL_SIGNATURE_KEY_USAGE) != CERT_DIGITAL_SIGNATURE_KEY_USAGE)
					continue;
			}
			else
			{	
				if (((pbKeyUsage[0] & CERT_DATA_ENCIPHERMENT_KEY_USAGE) != CERT_DATA_ENCIPHERMENT_KEY_USAGE) && 
					((pbKeyUsage[0] & CERT_KEY_ENCIPHERMENT_KEY_USAGE) != CERT_KEY_ENCIPHERMENT_KEY_USAGE))
					continue;
			}
		}

		m_pCertContext = pCertContext;


		char lpValue[500] = {0};
		ULONG ulLen = 500;
		get_SN(lpValue,&ulLen);
		if (0 ==  szCertId.compare(lpValue))
		{
			m_pCertContext = CertDuplicateCertificateContext(pCertContext);
			nRet = 0;
			break;
		}
	}

	if (pCertContext)
		CertFreeCertificateContext(pCertContext);
	CertCloseStore(hCertStore,0);
	return nRet;
}