#pragma once

#include "httpserver/HttpProtocol.h"
#include "reader.h"
#include "define.h"
#include <afxinet.h>

#define  SD_SETSIGNMETHOD       "standard/setSignMethod"
#define  SD_SETENCRYPTMETHOD    "standard /setEncryptMethod"
#define  SD_GETCERTINFO         "standard/getCertInfo"
#define  SD_GETCERTINFOBYOID    "standard/getCertInfoByOid"
#define  SD_VALIDDATECERT        "standard/validateCert"
#define  SD_VERIFYSIGNEDDATA     "standard/verifySignedData"
#define  SD_VERIFYSIGNEDFILE     "standard/verifySignedFile"
#define  SD_VERIFYSIGNEDDATABYP7 "standard/verifySignedDataByP7"
#define  SD_GETP7SIGNDATAINFO    "standard/getP7SignDataInfo"
#define  SD_VERIFYSIGNEDDATAXML  "standard/verifySignedDataXML"
#define  SD_GETXMLSIGNTUREINFO   "standard/getXMLSignatureInfo"
#define  SD_GENRANDOM            "standard/genRandom"
#define  SD_GETINSTANCE          "standard/getInstance"

class CParserSDMsg
{
public:
	CParserSDMsg(void);
	~CParserSDMsg(void);


	int PostHttpPage(std::string pathName, Json::Value& jsData,std::string& szOut);

	BOOL PreDealWithMsg(const std::string& szType,Json::Value& jsData, std::string& szOutData);
	int DealWithRecvMsg(const std::string& szType, std::string& szData);

	std::string m_szHostName;
	INTERNET_PORT m_nPort;
};
