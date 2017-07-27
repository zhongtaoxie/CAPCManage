#pragma once
#include "wincrypt.h"
class CCSPCertificate
{
public:
	CCSPCertificate(void);
	~CCSPCertificate(void);

	ULONG _DecodeX509Cert(LPBYTE lpCertData, ULONG ulDataLen);
	ULONG _DecodeP7bCert(LPBYTE lpCertData, ULONG ulDataLen);
	ULONG _DecodePfxCert(LPBYTE lpCertData, ULONG ulDataLen, LPSTR lpscPassword);
	ULONG get_SN(LPSTR lptcSN,ULONG *pulLen);
	ULONG get_KeyType(ULONG* pulType);
	ULONG get_KeyUsage(ULONG* lpUsage);
	ULONG get_Issuer(LPSTR lpValue, ULONG *pulLen);
	ULONG _GetPropertyValue(LPCSTR szOId, DWORD dwSourceId, LPSTR lpValue, DWORD &dwValLen);
	ULONG get_SubjectName(LPSTR lpValue, ULONG *pulLen);
	ULONG get_ValidDate(SYSTEMTIME *ptmStart, SYSTEMTIME *ptmEnd);

	ULONG gtDecryptData(std::string szData,std::string& szDecryptData);

	void setPcCert(PCCERT_CONTEXT pCertContext){m_pCertContext = pCertContext;};

	DWORD EnumCerts(BOOL bSig,std::string szCertId);

	std::string GetCertSubject();

	ULONG get_KeyHash(ULONG* pulType);

public:
	PCCERT_CONTEXT m_pCertContext;
};
