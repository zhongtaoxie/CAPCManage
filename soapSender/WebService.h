#ifndef _CDA_WEB_SERVICE_H
#define _CDA_WEB_SERVICE_H
#include "soapH.h"
class soapSender{
public:
	static std::string m_szServerIp;
	static int m_nServerPort;
	static int GetServerInfo(std::string szConfigFile);
	static void SetServerInfo(std::string szIP, int nPort);
	static int SOF_USCOREGenRandom(WS1__SOF_USCOREGenRandom& sofRequest, std::string& szResp,int nTimeOut=10);
	static int SOF_USCOREGetInstance(WS1__SOF_USCOREGetInstance& sofRequest,std::string& szResp, int nTimeOut=10);
	static int SOF_VerifySignedData(WS1__SOF_USCOREVerifySignedData& sofRequest,BOOL& bSuccess,int nTimeOut=10);
	static int SOF_QueryCertTrustList(WS1__SOF_USCOREQueryCertTrustList& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_VerifySignedDataByP7(WS1__SOF_USCOREVerifySignedDataByP7& sofRequest,BOOL& bSuccess,int nTimeOut=10);

	static int SOF_SetCertTrustList(WS1__SOF_USCORESetCertTrustList& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_GetP7SignDataInfo(WS1__SOF_USCOREGetP7SignDataInfo& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_VerifyTimeStamp(WS1__SOF_USCOREVerifyTimeStamp& sofRequest,BOOL& bSuccess,int nTimeOut=10);
	static int SOF_PubKeyEncrypt(WS1__SOF_USCOREPubKeyEncrypt& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_VerifySignedFile(WS1__SOF_USCOREVerifySignedFile& sofRequest,BOOL& bSuccess,int nTimeOut=10);

	static int SOF_GetServerCertificate(WS1__SOF_USCOREGetServerCertificate& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_GetCertInfoByOid(WS1__SOF_USCOREGetCertInfoByOid& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_DelCertTrustList(WS1__SOF_USCOREDelCertTrustList& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_GetXMLSignatureInfo(WS1__SOF_USCOREGetXMLSignatureInfo& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_VerifySignedDataXML(WS1__SOF_USCOREVerifySignedDataXML& sofRequest,BOOL& bSuccess,int nTimeOut=10);

	static int SOF_SignData(WS1__SOF_USCORESignData& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_SignFile(WS1__SOF_USCORESignFile& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_PriKeyDecrypt(WS1__SOF_USCOREPriKeyDecrypt& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_SetWebAppName(WS1__SOF_USCORESetWebAppName& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_GetSignMethod(WS1__SOF_USCOREGetSignMethod& sofRequest,std::string& szResp,int nTimeOut=10);

	static int SOF_SetEncryptMethod(WS1__SOF_USCORESetEncryptMethod& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_CreateTimeStampRequest(WS1__SOF_USCORECreateTimeStampRequest& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_GetEncryptMethod(WS1__SOF_USCOREGetEncryptMethod& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_CreateTimeStampResponse(WS1__SOF_USCORECreateTimeStampResponse& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_ValidateCert(WS1__SOF_USCOREValidateCert& sofRequest,int& nResp,int nTimeOut=10);

	static int SOF_DecryptFile(WS1__SOF_USCOREDecryptFile& sofRequest,BOOL& bSuccess,int nTimeOut=10);
	static int SOF_SetSignMethod(WS1__SOF_USCORESetSignMethod& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_GetTimeStampInfo(WS1__SOF_USCOREGetTimeStampInfo& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_SignDataByP7(WS1__SOF_USCORESignDataByP7& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_EncryptFile(WS1__SOF_USCOREEncryptFile& sofRequest,BOOL& bSuccess,int nTimeOut=10);

	static int SOF_SignDataXML(WS1__SOF_USCORESignDataXML& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_DecryptData(WS1__SOF_USCOREDecryptData& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_QueryCertTrustListAltNames(WS1__SOF_USCOREQueryCertTrustListAltNames& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_GetCertInfo(WS1__SOF_USCOREGetCertInfo& sofRequest,std::string& szResp,int nTimeOut=10);
	static int SOF_EncryptData(WS1__SOF_USCOREEncryptData& sofRequest,std::string& szResp,int nTimeOut=10);


	static std::string agentMessage(std::string szRequest, std::string szServerIp, int nServerPort = 80, int nTimeOut = 10);
};


#endif


