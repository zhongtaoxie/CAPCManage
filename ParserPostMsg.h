#pragma once

#include "httpserver/HttpProtocol.h"
#include "reader.h"
#include "define.h"

class CParserPostMsg
{
public:
	CParserPostMsg(void);
	~CParserPostMsg(void);
	int  Analyze(PREQUEST pReq, LPBYTE pBuf);
	int  Analyze2(PREQUEST pReq, LPBYTE pBuf);
	BOOL SendResp(std::string szResp);
	int GetTokenID(CString strInfo);

	int DealwithError(std::string szError);
	int DealwithLogin();
	int DealWithVersion();
	int DealwithSetSignMethod();
	int DealwithGetSignMethod();
	int SOF_SetEncryptMethodDW();
	int SOF_GetEncryptMethodDW();
	int SOF_GetUserListDW();
	int SOF_ExportUserCertDW();
	int SOF_LoginDW();
	int SOF_ChangePassWdDW();
	int SOF_ExportExChangeUserCertDW();
	int SOF_GetCertInfoDW();
	int SOF_GetCertInfoByOidDW();
	int SOF_GetUserInfoDW();
	int SOF_ValidateCertDW();

	int SOF_SignDataDW();
	int SOF_VerifySignedDataDW();
	int SOF_SignFileDW();
	int SOF_VerifySignedFileDW();
	int SOF_EncryptDataDW();
	int SOF_EncryptDataDWLoc();
	int SOF_DecryptDataDW();
	int SOF_EncryptFileDW();
	int SOF_DecryptFileDW();

	int SOF_PubKeyEncryptDW();
	int SOF_PriKeyDecryptDW();
	int SOF_SignDataByP7DW();
	int SOF_VerifySignedDataByP7DW();
	int SOF_GetP7SignDataInfoDW();
	int SOF_SignDataXMLDW();
	int SOF_VerifySignedDataXMLDW();
	int SOF_GetXMLSignatureInfoDW();
	int SOF_CheckSupportDW();
	int SOF_GenRandomDW();
	int SOF_GetInstanceDW();
	int SetServerDW();

	int SOF_EncryptDataDW2();
	int SOF_DecryptDataDW2();
	int SOF_DecryptDataDWLoc(std::string szSymmKey,std::string szIndata,std::string& szOutdata);
	int SOF_EncryptDataDWLoc(std::string szSymmKey,std::string szIndata,std::string& szOutdata);
	int SOF_EncryptFileDW2();
	int SOF_DecryptFileDW2();

	


	ReadCertInfo* GetCertInfo(std::string szCertId,BOOL bFirst= FALSE);
	int SendUserInfo(std::string szInfo);
	void ClearConnect();
	int ReadFileInfo(std::string szFilePath, std::string& szBuf);
	int WriteFileInfo(std::string szResName, const std::string& strBuf, std::string& szNewPath);

	void SetAsn1Value(BYTE* pbAllData);
	void SetAsn1Value2(BYTE* pbAllData);
	int SOF_SignDataDW(std::string szCertId, 
		               std::string szInData, 
		               std::string& szOutSignData,
		               std::string& szHashData,
		               ReadCertInfo*& pOutRCI);

	std::string GetCertKeyType(ReadCertInfo* pRCI);

	int JustMsgFormat(CString& strInfo);



	CString m_strBody;
	Json::Value m_inRoot; 
	PREQUEST m_pReq;
	CString m_strTokenId;

	INT32 m_nSignMethod;//签名方法
	INT32 m_nEncryptMethod;//加密方法
	int   m_nHashType;

	BOOL m_bSetIP;
//	std::string m_szOldData;
};
