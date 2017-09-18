#include "StdAfx.h"
#include "CAPCManage.h"
#include "ParserPostMsg.h"
#include <string.h>
#include "CAPCManageDlg.h"
#include "CSPCertificate.h"
#include "ReadUKey.h"
#include "../soapSender/WebService.h"
#include "PinDlg.h"
#include "HttpProtocol2.h"
#include "EnDecodeClass.h"
#include "Base64.h"
#include "XMLDOMParser.h"


extern CString g_strExePath;
extern CString g_strTokenId;
extern CCAPCManageDlg* g_pCADlg;
extern CReadUKey* g_readUKey;
ECCCIPHERBLOB  pEccCipherBlob ={0};
using namespace std;
CParserPostMsg::CParserPostMsg(void)
{
	m_pReq = NULL;
	m_nEncryptMethod = 0x101;
	m_nHashType = SGD_SHA1;
	m_bSetIP = FALSE;
}

CParserPostMsg::~CParserPostMsg(void)
{
}

int CParserPostMsg::GetTokenID(CString strInfo)
{
	int nFind = strInfo.Find("Token-ID:");
	if (-1 == nFind)
	{
		return -1;
	}

	int nEnd = strInfo.Find("\r\n",nFind);
	if (-1 == nEnd)
	{
		return -2;
	}

	int nLen = nEnd - (nFind+strlen("Token-ID:"));

	CString strTokenId = strInfo.Mid(nFind+strlen("Token-ID:"),nLen);
	strTokenId.Trim();
	m_strTokenId = strTokenId;
	g_strTokenId = m_strTokenId;//TokenId--xzt暂时没有用
	return 0;


}


int CParserPostMsg::JustMsgFormat(CString& strInfo)
{

	int nFind = strInfo.Find("POST /caclient");
	if (0 != nFind)
	{

		LOG_ERROR("Get msg type error,msg=%s",strInfo);
		return -2;//文件格式错误，数据抛弃
	}

	//GetTokenID(strInfo);

	//得到消息体
	nFind = strInfo.Find("Content-Length:");
	if (-1 == nFind)
	{
		LOG_ERROR("Get msg type error,msg=%s",strInfo);
		return-2;//文件格式错误，数据抛弃
	}

	//得到body体的长度
	int nEnd = strInfo.Find("\n",nFind);
	int nLen = nEnd - (nFind+strlen("Content-Length:"));
	CString strLen = strInfo.Mid(nFind+strlen("Content-Length:"),nLen);
	strLen.Trim();
	int nNum = atoi(strLen.GetBuffer());

	//
	int nBody = strInfo.Find("\r\n\r\n");
	if (-1 == nBody)
	{
		LOG_INFO("msg is not all,msg=%s",strInfo);
		return-1;
	}

	if ((nNum+nBody+4) != strInfo.GetLength())
	{
		LOG_INFO("msg is not all,msg=%s",strInfo);
		return-1;
	}


	m_strBody = strInfo.Right(nNum);
	std::string szTmp = m_strBody.GetBuffer();
	CEnDecodeClass::Utf2Gbk(szTmp);
	m_strBody = szTmp.c_str();


	return 0;
}

int  CParserPostMsg::Analyze(PREQUEST pReq, LPBYTE pBuf)
{
	
	m_pReq = pReq;


	CString strBody = m_strBody;
	m_strBody.Empty();

	LOG_INFO("The third interface input=%s",strBody);

	
	Json::Reader jReader;
	
	if (!jReader.parse(strBody.GetBuffer(), m_inRoot) || m_inRoot.isNull())  
	{
		LOG_INFO("input json format is invalid，strBody=%s",strBody);
		return (DealwithError("msg format error"));
	}
	else if (!m_inRoot.isObject())
	{
		LOG_INFO("input json format is invalid，strBody=%s",strBody);
		return (DealwithError("msg format error"));
	}

	CString strUrl = m_inRoot["url"].asString().c_str();
	m_strUrl = strUrl;

	if (0 == strUrl.Compare("SOF_SetServer")
		||0 == strUrl.Compare("SetServer"))
	{
		return(SetServerDW());
	}


	
	if (0 == strUrl.Compare("login"))//{"url":"login","tokenId":"1122334455"}
	{
		g_strTokenId = m_strTokenId;
		return(DealwithLogin());
	}
	else if (0 == strUrl.Compare("SOF_GetVersion")
		||0 == strUrl.Compare("GetVersion"))
	{
		return(DealWithVersion());
	
	}
	else if (0 == strUrl.Compare("SOF_SetSignMethod")
		||0 == strUrl.Compare("SetSignMethod"))
	{
		return(DealwithSetSignMethod());
	}
	else if (0 == strUrl.Compare("SOF_GetSignMethod")
		||0 == strUrl.Compare("GetSignMethod"))
	{
		return(DealwithGetSignMethod());
	}	
	else if (0 == strUrl.Compare("SOF_SetEncryptMethod")
		||0 == strUrl.Compare("SetEncryptMethod"))
	{
		return(SOF_SetEncryptMethodDW());
	}
	else if (0 == strUrl.Compare("SOF_GetEncryptMethod")
		||0 == strUrl.Compare("GetEncryptMethod"))
	{
		return(SOF_GetEncryptMethodDW());
	}
	else if (0 == strUrl.Compare("SOF_GetUserList")
		||0 == strUrl.Compare("GetUserList"))
	{
		return(SOF_GetUserListDW());
	}
	else if (0 == strUrl.Compare("SOF_ExportUserCert")
		||0 == strUrl.Compare("ExportUserCert"))
	{
		return(SOF_ExportUserCertDW());
	}
	else if (0 == strUrl.Compare("SOF_Login")
		||0 == strUrl.Compare("LoginSD"))
	{
		return(SOF_LoginDW());
	}
	else if (0 == strUrl.Compare("SOF_ChangePassWd")
		||0 == strUrl.Compare("ChangePassWd"))
	{
		return(SOF_ChangePassWdDW());
	}
	else if (0 == strUrl.Compare("SOF_ExportExChangeUserCert")
		||0 == strUrl.Compare("ExportExChangeUserCert"))
	{
		return(SOF_ExportExChangeUserCertDW());
	}
	else if (0 == strUrl.Compare("SOF_GetCertInfo")
		||0 == strUrl.Compare("GetCertInfo"))
	{
		return(SOF_GetCertInfoDW());
	}
	else if (0 == strUrl.Compare("SOF_GetCertInfoByOid")
		||0 == strUrl.Compare("GetCertInfoByOid"))
	{
		return(SOF_GetCertInfoByOidDW());
	}
	else if (0 == strUrl.Compare("SOF_GetUserInfo")
		||0 == strUrl.Compare("GetUserInfo"))
	{
		return(SOF_GetUserInfoDW());
	}
	else if (0 == strUrl.Compare("SOF_ValidateCert")
		||0 == strUrl.Compare("ValidateCert"))
	{
		return(SOF_ValidateCertDW());
	}
	else if (0 == strUrl.Compare("SOF_SignData")
		||0 == strUrl.Compare("SignData"))
	{
		return(SOF_SignDataDW());
	}
	else if (0 == strUrl.Compare("SOF_VerifySignedData")
		||0 == strUrl.Compare("VerifySignedData"))
	{
		return(SOF_VerifySignedDataDW());
	}
	else if (0 == strUrl.Compare("SOF_SignFile")
		||0 == strUrl.Compare("SignFile"))
	{
		return(SOF_SignFileDW());
	}
	else if (0 == strUrl.Compare("SOF_VerifySignedFile")
		||0 == strUrl.Compare("VerifySignedFile"))
	{
		return(SOF_VerifySignedFileDW());
	}
	else if (0 == strUrl.Compare("SOF_EncryptData")
		||0 == strUrl.Compare("EncryptData"))
	{
		return(SOF_EncryptDataDW2());
	}
	else if (0 == strUrl.Compare("SOF_DecryptData")
		||0 == strUrl.Compare("DecryptData"))
	{
		return(SOF_DecryptDataDW2());
	}
	else if (0 == strUrl.Compare("SOF_EncryptFile")
		||0 == strUrl.Compare("EncryptFile"))
	{
		return(SOF_EncryptFileDW2());
	}
	else if (0 == strUrl.Compare("SOF_DecryptFile")
		||0 == strUrl.Compare("DecryptFile"))
	{
		return(SOF_DecryptFileDW2());
	}
	else if (0 == strUrl.Compare("SOF_PubKeyEncrypt")
		||0 == strUrl.Compare("PubKeyEncrypt"))
	{
		return(SOF_PubKeyEncryptDW());
	}
	else if (0 == strUrl.Compare("SOF_PriKeyDecrypt")
		||0 == strUrl.Compare("PriKeyDecrypt"))
	{
		return(SOF_PriKeyDecryptDW());
	}
	else if (0 == strUrl.Compare("SOF_SignDataByP7")
		||0 == strUrl.Compare("SignDataByP7"))
	{
		return(SOF_SignDataByP7DW());
	}
	else if (0 == strUrl.Compare("SOF_VerifySignedDataByP7")
		||0 == strUrl.Compare("VerifySignedDataByP7"))
	{
		return(SOF_VerifySignedDataByP7DW());
	}
	else if (0 == strUrl.Compare("SOF_GetP7SignDataInfo")
		||0 == strUrl.Compare("GetP7SignDataInfo"))
	{
		return(SOF_GetP7SignDataInfoDW());
	}
	else if (0 == strUrl.Compare("SOF_SignDataXML")
		||0 == strUrl.Compare("SignDataXML"))
	{
		return(SOF_SignDataXMLDW());
	}
	else if (0 == strUrl.Compare("SOF_VerifySignedDataXML")
		||0 == strUrl.Compare("VerifySignedDataXML"))
	{
		return(SOF_VerifySignedDataXMLDW());
	}
	else if (0 == strUrl.Compare("SOF_GetXMLSignatureInfo")
		||0 == strUrl.Compare("GetXMLSignatureInfo"))
	{
		return(SOF_GetXMLSignatureInfoDW());
	}
	else if (0 == strUrl.Compare("SOF_CheckSupport")
		||0 == strUrl.Compare("CheckSupport"))
	{
		return(SOF_CheckSupportDW());
	}
	else if (0 == strUrl.Compare("SOF_GenRandom")
		||0 == strUrl.Compare("GenRandom"))
	{
		return(SOF_GenRandomDW());
	}
	else if (0 == strUrl.Compare("SOF_GetInstance")
		||0 == strUrl.Compare("GetInstance"))
	{
		return(SOF_GetInstanceDW());
	}
	else
	{
		return (DealwithError("msg format unknown"));
	}


	return -1;
}

void CParserPostMsg::ClearConnect()
{
	// 处理错误
	LOG_ERROR("Error occurs when analyzing client request");
	CHttpProtocol *pHttpProtocol = (CHttpProtocol *)m_pReq->pHttpProtocol;

	pHttpProtocol->Disconnect(m_pReq);
	delete m_pReq;
	pHttpProtocol->CountDown();     
}

int CParserPostMsg::DealwithError(std::string szError)
{
	Json::Value jsVal;
	jsVal["resultMsg"] =szError;
	jsVal["resultCode"] ="1";
	SendResp(jsVal.toStyledString());
	return 0;
}


int CParserPostMsg::DealwithSetSignMethod()
{
	/*if (0 != m_strTokenId.Compare(g_strTokenId))
	{
		DealwithError("Please before login");
		return 1;
	}*/

	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	if (!m_inRoot["SignMethod"].isInt())
	{
		DealwithError("interface format is error");
		return 1;
	}

	m_nSignMethod = m_inRoot["SignMethod"].asInt();
	std::string szResp;
	int nReturn_ = -1;

	if (0 == m_strUrl.Compare("SetSignMethod"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_SETSIGNMETHOD,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			nReturn_ =m_PSDM.DealWithRecvMsg("result",szResp);
		}
	}
	else
	{
		ns1__SOF_USCORESetSignMethod sofRequest;
		sofRequest.signMethod = m_nSignMethod;
		LOG_INFO("SOF_SetSignMethod:sofRequest.signMethod=%d",sofRequest.signMethod);
		nReturn_ = soapSender::SOF_SetSignMethod(sofRequest, szResp);
	}


	
	if (0 == nReturn_)
	{
		Json::Value jsVal;
		jsVal["resultCode"] = "0";

		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_SetSignMethod failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		DealwithError(strInfo.GetBuffer());
		LOG_ERROR(strInfo);
		return 1;
	}
	
}

int CParserPostMsg::DealwithGetSignMethod()
{
	/*if (0 != m_strTokenId.Compare(g_strTokenId))
	{
		DealwithError("Please before login");
		return 1;
	}*/
	Json::Value jsVal;
	
	jsVal["SignMethod"]=m_nSignMethod;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());
	return 0;
}

int CParserPostMsg::SOF_SetEncryptMethodDW()
{
	

	/*if (0 != m_strTokenId.Compare(g_strTokenId))
	{
		DealwithError("Please before login");
		return 1;
	}*/

	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	if (!m_inRoot["EncryptMethod"].isInt())
	{
		DealwithError("interface format is error");
		return 1;
	}

	m_nEncryptMethod = m_inRoot["EncryptMethod"].asInt();
	std::string szResp;
	int nReturn_ = -1;


	if (0 == m_strUrl.Compare("SetEncryptMethod"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_SETENCRYPTMETHOD,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			nReturn_ =m_PSDM.DealWithRecvMsg("result",szResp);
		}
	}
	else
	{
		ns1__SOF_USCORESetEncryptMethod sofRequest;
		sofRequest.encryptMethod = m_nEncryptMethod;
		LOG_INFO("SOF_SetEncryptMethod:sofRequest.encryptMethod=%d",sofRequest.encryptMethod);
		nReturn_ = soapSender::SOF_SetEncryptMethod(sofRequest, szResp);
	}

	
	if (0 == nReturn_)
	{
		Json::Value jsVal;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_SetEncryptMethod failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());

		DealwithError(strInfo.GetBuffer());
		LOG_ERROR(strInfo);
		return 1;
	}
}

int CParserPostMsg::SOF_GetEncryptMethodDW()
{
	Json::Value jsVal;
	
	jsVal["EncryptMethod"]=m_nEncryptMethod;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());
	return 0;
}

int CParserPostMsg::DealwithLogin()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	CHttpProtocol2 *pHttpProtocol = (CHttpProtocol2 *)m_pReq->pHttpProtocol;
	SendMessage(pHttpProtocol->m_hwndDlg, LOGIN_MSG, (WPARAM)m_pReq, NULL);
	return 0;
}

int CParserPostMsg::DealWithVersion()
{
	std::string szConfig = g_strExePath+"\\config\\config.ini";
	//得到软件版本
	TCHAR		szValueBuffer[100]			= {0};
	DWORD		dwValueBufferSize			= sizeof(szValueBuffer)/sizeof(TCHAR);
	GetPrivateProfileString("Common","version","",szValueBuffer,dwValueBufferSize,szConfig.c_str());
	Json::Value jsVal;
	
	jsVal["puiVersion"] = szValueBuffer;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());
	return 0;
}

int CParserPostMsg::SOF_GetUserListDW()
{
	//从Ukey中得到证书
	g_pCADlg->ClearData();
	g_pCADlg->CollectUSBInfo();
	g_pCADlg->ImportUKeyDlls();

	CString strInfo;
	int nCount = g_pCADlg->m_vecCert.size();
	for (int i =0; i< nCount;i++)
	{
		CCSPCertificate cspCert;
		cspCert._DecodeX509Cert(g_pCADlg->m_vecCert[i].m_pCert, g_pCADlg->m_vecCert[i].m_ulCertLen);

		//得到使用者
		char lpValue[500] = {0};
		ULONG ulLen = 500;
		cspCert.get_SubjectName(lpValue,&ulLen);

		//OID.2.5.4.88=00001, OID.2.5.4.26=市辖区, OID.2.5.4.45=entCert2, C=CN, S=江苏省, 
		//L=南京市, O=测试sm2证书20170427, OU=666, CN=测试sm2证书20170427
		CString strTmp = lpValue;
		int nFind = strTmp.Find("CN=");
		if (nFind != -1)
		{
			strTmp = strTmp.Right(strTmp.GetLength()-(nFind+3));
		}

		cspCert.get_SN(lpValue,&ulLen);

		if (!strInfo.IsEmpty())
		{
			strInfo +="&&&";
		}

		strInfo +=strTmp;
		strInfo +="||";
		strInfo +=lpValue;
	}

	Json::Value jsVal;
	
	jsVal["UserList"] = strInfo.GetBuffer();
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());
	return 0;
}

int CParserPostMsg::SOF_ExportUserCertDW()
{
	//从Ukey中得到证书
	g_pCADlg->ClearData();
	g_pCADlg->CollectUSBInfo();
	g_pCADlg->ImportUKeyDlls();

	std::string szCertId = m_inRoot["CertID"].asString();

//	unsigned char szBuf[200]={0};
//	int nbase64 = Base64Decode(szBuf, szCertId.c_str());

	int nCount = g_pCADlg->m_vecCert.size();
	for (int i =0; i< nCount;i++)
	{
		CCSPCertificate cspCert;
		cspCert._DecodeX509Cert(g_pCADlg->m_vecCert[i].m_pCert, g_pCADlg->m_vecCert[i].m_ulCertLen);

		char lpValue[500] = {0};
		ULONG ulLen = 500;
		cspCert.get_SN(lpValue,&ulLen);
		if (0 ==  szCertId.compare(lpValue) && g_pCADlg->m_vecCert[i].m_bSignFlag)
		{
			char* szBuf = new char[g_pCADlg->m_vecCert[i].m_ulCertLen*2];
			memset(szBuf, 0, g_pCADlg->m_vecCert[i].m_ulCertLen*2);
			int nbase64 = Base64Encode(szBuf,g_pCADlg->m_vecCert[i].m_pCert,g_pCADlg->m_vecCert[i].m_ulCertLen);


			Json::Value jsVal;
			jsVal["resultCode"] = "0";
			jsVal["UserCert"] = szBuf;
			
			SendResp(jsVal.toStyledString());
			return 0;
		}
	}

	LOG_INFO("no find cert by certid=%s",szCertId.c_str());

	DealwithError("no find cert");
	return 1;
	
}

int CParserPostMsg::SOF_LoginDW()
{
	//从Ukey中得到证书
	g_pCADlg->ClearData();
	g_pCADlg->CollectUSBInfo();
	g_pCADlg->ImportUKeyDlls();

	std::string szCertId = m_inRoot["CertID"].asString();
	std::string szPassWd = m_inRoot["PassWd"].asString();
	int nCount = g_pCADlg->m_vecCert.size();
	for (int i =0; i< nCount;i++)
	{
		CCSPCertificate cspCert;
		cspCert._DecodeX509Cert(g_pCADlg->m_vecCert[i].m_pCert, g_pCADlg->m_vecCert[i].m_ulCertLen);

		char lpValue[500] = {0};
		ULONG ulLen = 500;
		cspCert.get_SN(lpValue,&ulLen);
		if (0 ==  szCertId.compare(lpValue))
		{

			CReadUKey* pReadUKey = (CReadUKey*)g_pCADlg->m_vecCert[i].m_pReadUkey;
			ULONG ulRetryCount=0;
			int rv = pReadUKey->CheckPin(g_pCADlg->m_vecCert[i].m_hDev,g_pCADlg->m_vecCert[i].m_hApp,szPassWd,ulRetryCount);
			if (rv)
			{
				if (ulRetryCount==0)
				{
					Json::Value jsVal;
					jsVal["resultMsg"] ="passWd is error,You have not more chances.";
					jsVal["resultCode"] ="-1";
					SendResp(jsVal.toStyledString());
					return 1;
				}
				else
				{
					CString strMsg;
					strMsg.Format("passWd is error,You have %d more chances.",ulRetryCount);
					DealwithError(strMsg.GetBuffer());
					return 1;
				}
				
			}
			else
			{
				Json::Value jsVal;
				jsVal["resultCode"] = "0";
				SendResp(jsVal.toStyledString());
				return 0;
			}
			
		}
	}

	DealwithError("Not find cert");

	return 1;
}

int CParserPostMsg::SOF_ChangePassWdDW()
{
	std::string szCertId = m_inRoot["CertID"].asString();
	std::string szOldPassWd = m_inRoot["OldPassWd"].asString();
	std::string szNewPassWd = m_inRoot["NewPassWd"].asString();

	//得到证书信息
	ReadCertInfo* pRCI = GetCertInfo(szCertId);
	if (NULL == pRCI)
	{
		DealwithError("no find cert");
		return 1;
	}

	//得到UKey的解析器
	CReadUKey* pReadUKey = (CReadUKey*)pRCI->m_pReadUkey;

	ULONG rv = SAR_OK,ulRetryCount =0;
	rv = pReadUKey->m_PSKF_ChangePIN(pRCI->m_hApp,USER_TYPE,(LPSTR)szOldPassWd.c_str(),(LPSTR)szNewPassWd.c_str(),&ulRetryCount);

	if (rv)
	{
		CString strData;
		strData.Format("Change password failed,you have %d more chances.",ulRetryCount);
		DealwithError(strData.GetBuffer());
		return 1;
	}
	else
	{
		Json::Value jsVal;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}

	return 0;
}

int CParserPostMsg::SOF_ExportExChangeUserCertDW()
{
	//从Ukey中得到证书
	g_pCADlg->ClearData();
	g_pCADlg->CollectUSBInfo();
	g_pCADlg->ImportUKeyDlls();

	std::string szCertId = m_inRoot["CertID"].asString();
	int nCount = g_pCADlg->m_vecCert.size();
	for (int i =0; i< nCount;i++)
	{
		CCSPCertificate cspCert;
		cspCert._DecodeX509Cert(g_pCADlg->m_vecCert[i].m_pCert, g_pCADlg->m_vecCert[i].m_ulCertLen);

		char lpValue[500] = {0};
		ULONG ulLen = 500;
		cspCert.get_SN(lpValue,&ulLen);
		if (0 ==  szCertId.compare(lpValue) && !(g_pCADlg->m_vecCert[i].m_bSignFlag))
		{
			char* szBuf = new char[g_pCADlg->m_vecCert[i].m_ulCertLen*2];
			memset(szBuf, 0, g_pCADlg->m_vecCert[i].m_ulCertLen*2);
			int nbase64 = Base64Encode(szBuf,g_pCADlg->m_vecCert[i].m_pCert,g_pCADlg->m_vecCert[i].m_ulCertLen);


			Json::Value jsVal;
			
			jsVal["UserCert"] = szBuf;
			jsVal["resultCode"] = "0";
			SendResp(jsVal.toStyledString());
			return 0;
		}
	}

	LOG_INFO("no find cert by certid=%s",szCertId.c_str());

	DealwithError("no find cert");
	return 1;

}

int CParserPostMsg::SOF_GetCertInfoDW()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	if (!m_inRoot["Type"].isInt())
	{
		DealwithError("interface format is error");
		return 1;
	}


	std::string szCert = m_inRoot["Cert"].asString();
	int nType = m_inRoot["Type"].asInt();
	std::string szResp;
	int nReturn_ = -1;


	if (0 == m_strUrl.Compare("GetCertInfo"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_GETCERTINFO,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			std::string szTmp = szResp;
			nReturn_ =m_PSDM.DealWithRecvMsg("resultCode",szResp);
			if (0 == nReturn_ && 0 == szResp.compare("0"))
			{
				szResp = szTmp;
				nReturn_ =m_PSDM.DealWithRecvMsg("resultData",szResp);
			}
			else
			{
				nReturn_ =1;
			}
		}
	}
	else
	{
		ns1__SOF_USCOREGetCertInfo sofRequest;
		sofRequest.base64EncodeCert = &szCert;
		sofRequest.type = nType;
		LOG_INFO("SOF_GetCertInfo:sofRequest.base64EncodeCert=%s,\r\nsofRequest.type=%d",
			sofRequest.base64EncodeCert->c_str(),
			sofRequest.type);

		nReturn_ = soapSender::SOF_GetCertInfo(sofRequest, szResp);
	}


	
	if (0 == nReturn_)
	{
		Base64 bs64;
		std::string szTmp = bs64.base64_decode(szResp);
		CEnDecodeClass::Utf2Gbk(szTmp);

		Json::Value jsVal;
		jsVal["UserCertInfo"] = szTmp;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{

		CString strInfo;
		strInfo.Format("SOF_GetCertInfo failed from server! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		
		DealwithError(strInfo.GetBuffer());
		LOG_ERROR(strInfo);
		return 1;

	}
}

int CParserPostMsg::SOF_GetCertInfoByOidDW()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	std::string szCert = m_inRoot["Cert"].asString();
	std::string szOid = m_inRoot["Oid"].asString();

	std::string szResp;
	int nReturn_ = -1;


	if (0 == m_strUrl.Compare("GetCertInfoByOid"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_GETCERTINFOBYOID,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			std::string szTmp = szResp;
			nReturn_ =m_PSDM.DealWithRecvMsg("resultCode",szResp);
			if (0 == nReturn_ && 0 == szResp.compare("0"))
			{
				szResp = szTmp;
				nReturn_ =m_PSDM.DealWithRecvMsg("resultData",szResp);
			}
			else
			{
				nReturn_ =1;
			}
		}
	}
	else
	{
		ns1__SOF_USCOREGetCertInfoByOid sofRequest;
		sofRequest.base64EncodeCert = &szCert;
		sofRequest.oid = &szOid;
		LOG_INFO("SOF_GetCertInfoByOid:sofRequest.base64EncodeCert=%s,\r\nsofRequest.oid=%s",
			sofRequest.base64EncodeCert->c_str(),
			sofRequest.oid->c_str());
		nReturn_ = soapSender::SOF_GetCertInfoByOid(sofRequest, szResp);
	}

	
	if (0 == nReturn_)
	{
		Json::Value jsVal;
		
		jsVal["UserCertInfo"] = szResp;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{

		CString strInfo;
		strInfo.Format("SOF_GetCertInfoByOid failed from server! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());

		DealwithError(strInfo.GetBuffer());
		LOG_ERROR(strInfo);
		return 1;

	}
}

std::string CParserPostMsg::GetCertKeyType(ReadCertInfo* pRCI)
{
	int nNum =0;
	int nCount = g_pCADlg->m_vecCert.size();
	for (int i =0; i< nCount;i++)
	{
		if (g_pCADlg->m_vecCert[i].m_hAContainer == pRCI->m_hAContainer)
		{
			nNum++;
		}
	}

	if (nNum !=1)
	{
		return (std::string("单证"));
	}
	else
	{
		return (std::string("单证"));
	}
}
///////////////////////////先搭建框架，后面再实现--xzt
int CParserPostMsg::SOF_GetUserInfoDW()
{
	if (!m_inRoot["type"].isInt())
	{
		DealwithError("interface format is error");
		return 1;
	}

	std::string szCertId = m_inRoot["CertID"].asString();
	
	int nType = m_inRoot["type"].asInt();

	//得到证书信息
	ReadCertInfo* pRCI = GetCertInfo(szCertId);
	if (NULL == pRCI)
	{
		DealwithError("no find cert");
		return 1;
	}

	DWORD dwLen = 3000;
	char szRetBuf[3000] = {0};

	CCSPCertificate cspCert;
	cspCert._DecodeX509Cert(pRCI->m_pCert, pRCI->m_ulCertLen);
	PCCERT_CONTEXT pCertContext = cspCert.m_pCertContext;

	switch(nType)
	{
	case CERT_SUBJECT:
		  {
			  dwLen = CertGetNameString(cspCert.m_pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
			  CertGetNameString(cspCert.m_pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,0, NULL,  szRetBuf, dwLen + 1);
			  dwLen = strlen(szRetBuf);
			  break;
		  }
	case CERT_UNIQUEID:
		 {
			  cspCert.get_SN(szRetBuf,&dwLen);
			 break;
		 }
	case CERT_DEPT:
		 {
			 dwLen = CertGetNameString(pCertContext, CERT_NAME_ATTR_TYPE,0, szOID_ORGANIZATIONAL_UNIT_NAME, NULL, 0);
			 CertGetNameString(pCertContext, CERT_NAME_ATTR_TYPE,0, szOID_ORGANIZATIONAL_UNIT_NAME,  szRetBuf, dwLen + 1);
			 dwLen = strlen(szRetBuf);
			 break;
		 }
	case CERT_ISSUE:
		 {
			 cspCert.get_Issuer(szRetBuf,&dwLen);
			 break;
		 }
	case CERT_DEVICETYPE://证书介质类型
		{
			strcpy(szRetBuf, ((CReadUKey*)(pRCI->m_pReadUkey))->m_szDevName.c_str());
			dwLen = strlen(szRetBuf);
			break;
		}
	case CERT_CATYPE://CA类型
		{
			strcpy(szRetBuf, "江苏CA");
			dwLen = strlen(szRetBuf);
			break;
		}
	case CERT_KEYTYPE://用户证书密钥类型，（双证或单证）
		{
			strcpy(szRetBuf, GetCertKeyType(pRCI).c_str());
			dwLen = strlen(szRetBuf);
			break;
		}		
		
	case CERT_DEVICENAME://用户证书介质名称
		{
			strcpy(szRetBuf, ((CReadUKey*)(pRCI->m_pReadUkey))->m_szDevName.c_str());
			dwLen = strlen(szRetBuf);
			break;
		}
	case CERT_DEVICEPROVIDER://用户证书介质提供者即csp名称
		{
			strcpy(szRetBuf, ((CReadUKey*)(pRCI->m_pReadUkey))->m_szDevName.c_str());
			dwLen = strlen(szRetBuf);
			break;
		}
	case CERT_DEVICEAFFIX://用户证书介质附加库
		{
			strcpy(szRetBuf, ((CReadUKey*)(pRCI->m_pReadUkey))->m_szDLLName.c_str());
			dwLen = strlen(szRetBuf);
			break;
		}
	case CERT_SIGNPATH://用户签名证书路径
		{
			strcpy(szRetBuf, pRCI->m_byPath);
			dwLen = strlen(szRetBuf);
			break;
		}
	case CERT_EXCHPATH://用户加密证书路径
		{
			strcpy(szRetBuf, pRCI->m_byPath);
			dwLen = strlen(szRetBuf);
			break;
		}
	case CERT_SIGNPFXPATH://用户签名P12证书路径
		{
			//strcpy(szRetBuf, "unknown");
			//dwLen = strlen(szRetBuf);
			break;
		}
	case CERT_EXCHPFXPATH://用户加密P12证书路径
		{
			//strcpy(szRetBuf, "unknown");
			//dwLen = strlen(szRetBuf);
			break;
		}
	case CERT_UNIQUEIDOID://用户证书UniqueID的OID
		{
			//cspCert.GetCertSubject();
			strcpy(szRetBuf, "1.2.86.21.1.1");
			dwLen = strlen(szRetBuf);
			break;
		}
	default:
		{
			DealwithError("unknown type");
			return -1;
			break;
		}
	}
	

	Json::Value jsVal;

	jsVal["UserCertInfo"] = szRetBuf;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());


	return 0;

}

int CParserPostMsg::SOF_ValidateCertDW()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	std::string szCert = m_inRoot["Cert"].asString();

	std::string szResp;
	int nReturn_ = -1;
	int nResp = 0;


	if (0 == m_strUrl.Compare("ValidateCert"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_VALIDDATECERT,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			nReturn_ =m_PSDM.DealWithRecvMsg("result",szResp);
			if (0 == nReturn_)
			{
				nResp = atoi(szResp.c_str());
			}
		}
	}
	else
	{
		ns1__SOF_USCOREValidateCert sofRequest;
		sofRequest.base64EncodeCert = &szCert;
		LOG_INFO("SOF_ValidateCert:sofRequest.base64EncodeCert=%s",
			sofRequest.base64EncodeCert->c_str());
		nReturn_ = soapSender::SOF_ValidateCert(sofRequest, nResp);
	}


	
	if (1 == nResp)
	{
		Json::Value jsVal;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{

		CString strInfo;
		strInfo.Format("SOF_ValidateCert failed from server! nReturn_=%d,nResp=%d",nReturn_, nResp);
		LOG_ERROR(strInfo);
		if (-1 == nResp)
		{
			DealwithError("证书无效，不是所信任的根");
		}
		else if (-2 == nResp)
		{
			DealwithError("证书无效，超过有效期");
		}
		else if (-3 == nResp)
		{
			DealwithError("证书无效，为作废证书");
		}
		else if (-4 == nResp)
		{
			DealwithError("证书无效，已加入黑名单");
		}
		else
		{
			DealwithError(strInfo.GetBuffer());
		}

		
		
		return 1;

	}
}

void CParserPostMsg::SetAsn1Value(BYTE* pbAllData)
{
	pbAllData[0]=0x30;
	pbAllData[1]=0x21;
	pbAllData[2]=0x30;
	pbAllData[3]=0x09;
	pbAllData[4]=0x06;
	pbAllData[5]=0x05;

	pbAllData[6]=0x2B;
	pbAllData[7]=0x0E;
	pbAllData[8]=0x03;
	pbAllData[9]=0x02;
	pbAllData[10]=0x1A;

	pbAllData[11]=0x05;
	pbAllData[12]=0x00;
	pbAllData[13]=0x04;
	pbAllData[14]=0x14;
}

void CParserPostMsg::SetAsn1Value2(BYTE* pbAllData)
{
	pbAllData[0]=0x30;
	pbAllData[1]=0x2F;
	pbAllData[2]=0x30;
	pbAllData[3]=0x09;
	pbAllData[4]=0x06;
	pbAllData[5]=0x05;

	pbAllData[6]=0x2B;
	pbAllData[7]=0x0E;
	pbAllData[8]=0x03;
	pbAllData[9]=0x02;
	pbAllData[10]=0x1A;

	pbAllData[11]=0x05;
	pbAllData[12]=0x00;
	pbAllData[13]=0x04;
	pbAllData[14]=0x20;
}

int CParserPostMsg::SOF_SignDataDW(std::string szCertId, 
								   std::string szInData, 
								   std::string& szOutSignData,
								   std::string& szHashData,
								   ReadCertInfo*& pOutRCI)
{
	//得到证书信息
	ReadCertInfo* pRCI = GetCertInfo(szCertId);
	if (NULL == pRCI)
	{
		DealwithError("no find cert");
		return 1;
	}

	pOutRCI = pRCI;

	CReadUKey* pReadUKey = (CReadUKey*)pRCI->m_pReadUkey;
	pReadUKey->m_hDev = pRCI->m_hDev;
	pReadUKey->m_hApp = pRCI->m_hApp;
	g_readUKey = pReadUKey;
	BYTE* pbSignature = NULL;
	ULONG ulSignLen = 0;

	CPinDlg dlg;
	if (IDOK == dlg.DoModal())
	{

		
		//得到证书类型
		CCSPCertificate cspCert;
		cspCert._DecodeX509Cert(pRCI->m_pCert, pRCI->m_ulCertLen);
		cspCert.get_KeyType(&(pReadUKey->m_ulType));
		ULONG nType=0;
		
		ULONG rv = 0;
		BYTE* pbHashData = NULL;
		ULONG ulHashLen=0;
		BYTE pbAllData[35]={0};
		if (pReadUKey->m_ulType == CERT_KEY_ALG_RSA)
		{
			
			cspCert.get_KeyHash(&nType);
			m_nHashType = nType;
			//得到待签名值的hash值
			if (SGD_SHA256 == nType)
			{
				rv = pReadUKey->DigestEx2(szInData,pRCI->m_hDev,pbHashData,&ulHashLen,nType);
			}
			else
			{
				rv = pReadUKey->DigestEx(szInData,pRCI->m_hDev,pbHashData,&ulHashLen,nType);
			}
			
			if (rv)
			{
				LOG_INFO("对数据进行hash失败！ 数据=%s", szInData.c_str());
				DealwithError("sign data failed");
				return 1;

			}

			if (SGD_SM3 == nType)
			{
				rv = pReadUKey->RSASignDataEx2(pRCI->m_hAContainer,pbHashData,ulHashLen, pbSignature, &ulSignLen);
			}
			else if (SGD_SHA1 == nType)
			{
				SetAsn1Value(pbAllData);
				memcpy(pbAllData+15,pbHashData,ulHashLen);
				rv = pReadUKey->RSASignDataEx2(pRCI->m_hAContainer,pbAllData,35, pbSignature, &ulSignLen);
			}
			else
			{
				//SetAsn1Value2(pbAllData);
				//memcpy(pbAllData+15,pbHashData,ulHashLen);
				//rv = pReadUKey->RSASignDataEx2(pRCI->m_hAContainer,pbAllData,47, pbSignature, &ulSignLen);
				rv = pReadUKey->RSASignDataEx2(pRCI->m_hAContainer,pbHashData,ulHashLen, pbSignature, &ulSignLen);
			}
		}
		else
		{
			//得到待签名值的hash值
			rv = pReadUKey->DigestEx(szInData,pRCI->m_hDev,pbHashData,&ulHashLen,SGD_SM3);
			if (rv)
			{
				LOG_INFO("对数据进行hash失败！ 数据=%s", szInData.c_str());
				DealwithError("sign data failed");
				return 1;
			}

			rv = pReadUKey->ECCSignDataEx2(pRCI->m_hAContainer,pbHashData,ulHashLen, pbSignature, &ulSignLen);
		}


		if (rv)
		{
			if (pbSignature!= NULL)
			{
				free(pbSignature);
				pbSignature = NULL;
			}


			//打印出随机数和证书内容
			char* szBuf = new char[pRCI->m_ulCertLen*2];
			memset(szBuf, 0, pRCI->m_ulCertLen*2);
			int nbase64 = Base64Encode(szBuf,pRCI->m_pCert,pRCI->m_ulCertLen);
			LOG_INFO("对数据进行签名失败！ 数据=%s,证书内容=%s", szInData.c_str(),szBuf);
			delete szBuf;

			DealwithError("sign data failed");
			return 1;
		}
		else
		{
			Base64 bs64;
			if (pReadUKey->m_ulType == CERT_KEY_ALG_RSA)
			{
				if (SGD_SM3 == nType)
				{
					szHashData = bs64.B64_Encode(pbHashData,ulHashLen);
				}
				else if (SGD_SHA256 == nType)
				{
					szHashData = bs64.B64_Encode(pbHashData,ulHashLen);
					//szHashData = bs64.B64_Encode(pbAllData,47);
				}
				else
				{
					szHashData = bs64.B64_Encode(pbAllData,35);
				}
				
			}
			else
			{
				szHashData = bs64.B64_Encode(pbHashData,ulHashLen);
			}
			
			szOutSignData = bs64.B64_Encode(pbSignature,ulSignLen);
			
			return 0;

		}
	}
	else
	{
		DealwithError("pin code is error");
		return 1;
	}

}

int CParserPostMsg::SOF_SignDataDW()
{
	std::string szOutSignData;
	std::string szhashData;
	ReadCertInfo* pOutRCI = NULL;

	if (0 == SOF_SignDataDW(m_inRoot["CertID"].asString(),m_inRoot["InData"].asString(),szOutSignData,szhashData,pOutRCI))
	{
		Json::Value jsVal;
		jsVal["SignData"] = szOutSignData;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}

	return 1;
}
int CParserPostMsg::SOF_VerifySignedDataDW()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	std::string szCert = m_inRoot["Cert"].asString();
	std::string szInData = m_inRoot["InData"].asString();
	std::string szSignValue = m_inRoot["SignValue"].asString();

	std::string szResp;
	int nReturn_ = -1;
	int nResp = 0;
	BOOL bResp = FALSE;


	if (0 == m_strUrl.Compare("VerifySignedData"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_VERIFYSIGNEDDATA,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			nReturn_ =m_PSDM.DealWithRecvMsg("result",szResp);
			if (0 == nReturn_)
			{
				nResp = atoi(szResp.c_str());
				if (0 == nResp)
				{
					bResp = FALSE;
				}
				else
				{
					bResp = TRUE;
				}
			}
		}
	}
	else
	{
		ns1__SOF_USCOREVerifySignedData sofRequest;
		sofRequest.inData = &szInData;
		sofRequest.signValue = &szSignValue;
		sofRequest.base64EncodeCert =&szCert;
		LOG_INFO("soapSender::SOF_VerifySignedData");
		nReturn_ = soapSender::SOF_VerifySignedData(sofRequest, bResp);
	}

	
	if (bResp)
	{
		Json::Value jsVal;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;

	}
	else
	{
		DealwithError("Verify signedData failed");
		return 1;
	}

}

int CParserPostMsg::SOF_SignFileDW()
{
	std::string szInFile = m_inRoot["InFile"].asString();
	//得到签名数据
	std::string szInData;
	if (ReadFileInfo(szInFile,szInData))
	{
		DealwithError("file is not exist");
		return 1;
	}

	std::string szOutSignData;
	std::string szhashData;
	ReadCertInfo* pOutRCI = NULL;
	if (0 == SOF_SignDataDW(m_inRoot["CertID"].asString(),szInData,szOutSignData,szhashData,pOutRCI))
	{
		Json::Value jsVal;
		jsVal["SignData"] = szOutSignData;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}

	return 1;
}
int CParserPostMsg::SOF_VerifySignedFileDW()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	std::string szCert = m_inRoot["Cert"].asString();
	std::string szInFile = m_inRoot["InFile"].asString();
	std::string szSignValue = m_inRoot["SignValue"].asString();

	std::string szInData;
	if (ReadFileInfo(szInFile,szInData))
	{
		DealwithError("file is not exist");
		return 1;
	}

	if("VerifySignedFile" == m_strUrl)
	{
		m_inRoot["inData"] = szInData;
	}

	std::string szResp;
	int nReturn_ = -1;
	int nResp = 0;
	BOOL bResp = FALSE;


	if (0 == m_strUrl.Compare("VerifySignedFile"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_VERIFYSIGNEDDATA,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			nReturn_ =m_PSDM.DealWithRecvMsg("result",szResp);
			if (0 == nReturn_)
			{
				nResp = atoi(szResp.c_str());
				if (0 == nResp)
				{
					bResp = FALSE;
				}
				else
				{
					bResp = TRUE;
				}
			}
		}
	}
	else
	{
		ns1__SOF_USCOREVerifySignedData sofRequest;
		sofRequest.inData = &szInData;
		sofRequest.signValue = &szSignValue;
		sofRequest.base64EncodeCert =&szCert;

		LOG_INFO("soapSender::SOF_VerifySignedData");
		nReturn_ = soapSender::SOF_VerifySignedData(sofRequest, bResp);
	}

	if (bResp)
	{
		Json::Value jsVal;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;

	}
	else
	{
		DealwithError("Verify signedFile failed");
		return 1;
	}

}



int CParserPostMsg::SOF_EncryptDataDWLoc(std::string szSymmKey,std::string szIndata,std::string& szOutdata)
{
	if (szSymmKey.length() !=16)
	{
		DealwithError("密钥长度必须是16位");
		return 1;
	}
	DWORD dwRet = 0, dwInDataLen = 0, dwOutDataLen = 0;
	HANDLE hKey = NULL;
	BYTE *pbOutData = NULL, *pbInData = NULL;
	BYTE bKey[0x20] = {0};
	DWORD dwKeyLen = 0, dwBlockNum = 0;
	Base64 Base64;



	//得到KEY
	//dwKeyLen = strlen(p);
	memcpy(bKey, szSymmKey.c_str(), 16);

	//得到数据

	dwInDataLen = szIndata.length();
	pbInData = new BYTE[dwInDataLen+16];
	memset(pbInData, 0x00, dwInDataLen+16);
	memcpy(pbInData, szIndata.c_str(), dwInDataLen);

	if (dwInDataLen%16)
	{
		dwBlockNum = dwInDataLen/16;
		dwBlockNum = dwBlockNum+1;
		dwInDataLen = dwBlockNum*16;
	}




	ReadCertInfo* pRCI =GetCertInfo("",TRUE);
	if (NULL == pRCI)
	{
		DealwithError("no find cert");
		return 1;
	}

	CReadUKey* pReadUKey = (CReadUKey*)pRCI->m_pReadUkey;

	dwRet = pReadUKey->m_PSKF_SetSymmKey(pRCI->m_hDev, bKey,m_nEncryptMethod, &hKey);
	if (dwRet)
	{
		DealwithError("m_PSKF_SetSymmKey failed");
		delete []pbInData;
		return dwRet;
	}

	BLOCKCIPHERPARAM EncryptParam;
	memset((char *)&EncryptParam,0x00,sizeof(BLOCKCIPHERPARAM));
	dwRet = pReadUKey->m_PSKF_EncryptInit(hKey,EncryptParam);
	if (dwRet)
	{
		DealwithError("m_PSKF_EncryptInit failed");
		delete []pbInData;
		return dwRet;
	}

	dwRet = pReadUKey->m_PSKF_Encrypt(hKey, pbInData, dwInDataLen, pbOutData, &dwOutDataLen);
	if (dwRet)
	{
		DealwithError("m_PSKF_Encrypt failed");
		delete []pbInData;
		return dwRet;
	}

	//申请输入数据空间和大小
	pbOutData = new BYTE[dwOutDataLen+1];
	memset(pbOutData, 0x00, dwOutDataLen+1);
	dwRet = pReadUKey->m_PSKF_Encrypt(hKey, pbInData, dwInDataLen, pbOutData, &dwOutDataLen);
	if (dwRet)
	{
		DealwithError("m_PSKF_Encrypt failed");
		delete []pbOutData;
		delete []pbInData;
		return dwRet;
	}

	szOutdata = Base64.base64_encode(pbOutData,dwOutDataLen);

	delete []pbOutData;
	delete []pbInData;

	return 0;

}

int CParserPostMsg::SOF_EncryptFileDWLoc(std::string szSymmKey,BYTE* btBuf, long lLen,std::string szInFile)
{
	if (szSymmKey.length() !=16)
	{
		DealwithError("密钥长度必须是16位");
		return 1;
	}
	DWORD dwRet = 0, dwInDataLen = 0, dwOutDataLen = 0;
	HANDLE hKey = NULL;
	BYTE *pbOutData = NULL, *pbInData = NULL;
	BYTE bKey[0x20] = {0};
	DWORD dwKeyLen = 0, dwBlockNum = 0;
	Base64 Base64;



	//得到KEY
	//dwKeyLen = strlen(p);
	memcpy(bKey, szSymmKey.c_str(), 16);

	//得到数据

	dwInDataLen = lLen;
	pbInData = new BYTE[dwInDataLen+16];
	memset(pbInData, 0x00, dwInDataLen+16);
	memcpy(pbInData, btBuf, dwInDataLen);

	if (dwInDataLen%16)
	{
		dwBlockNum = dwInDataLen/16;
		dwBlockNum = dwBlockNum+1;
		dwInDataLen = dwBlockNum*16;
	}




	ReadCertInfo* pRCI =GetCertInfo("",TRUE);
	if (NULL == pRCI)
	{
		DealwithError("no find cert");
		return 1;
	}

	CReadUKey* pReadUKey = (CReadUKey*)pRCI->m_pReadUkey;

	dwRet = pReadUKey->m_PSKF_SetSymmKey(pRCI->m_hDev, bKey,m_nEncryptMethod, &hKey);
	if (dwRet)
	{
		DealwithError("m_PSKF_SetSymmKey failed");
		delete []pbInData;
		return dwRet;
	}

	BLOCKCIPHERPARAM EncryptParam;
	memset((char *)&EncryptParam,0x00,sizeof(BLOCKCIPHERPARAM));
	dwRet = pReadUKey->m_PSKF_EncryptInit(hKey,EncryptParam);
	if (dwRet)
	{
		DealwithError("m_PSKF_EncryptInit failed");
		delete []pbInData;
		return dwRet;
	}

	dwRet = pReadUKey->m_PSKF_Encrypt(hKey, pbInData, dwInDataLen, pbOutData, &dwOutDataLen);
	if (dwRet)
	{
		DealwithError("m_PSKF_Encrypt failed");
		delete []pbInData;
		return dwRet;
	}

	//申请输入数据空间和大小
	pbOutData = new BYTE[dwOutDataLen+1];
	memset(pbOutData, 0x00, dwOutDataLen+1);
	dwRet = pReadUKey->m_PSKF_Encrypt(hKey, pbInData, dwInDataLen, pbOutData, &dwOutDataLen);
	if (dwRet)
	{
		DealwithError("m_PSKF_Encrypt failed");
		delete []pbOutData;
		delete []pbInData;
		return dwRet;
	}

	std::string szOutdata = Base64.base64_encode(pbOutData,dwOutDataLen);


	FILE    *fp;
	fp=fopen(szInFile.c_str() ,"wb+");
	if(!fp)
	{
		DealwithError("m_PSKF_Encrypt failed");
		delete []pbOutData;
		delete []pbInData;
		return -1;
	}

	int len = fwrite(szOutdata.c_str(), 1,szOutdata.length() ,fp);
	fclose(fp);

	Json::Value jsVal;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());


	delete []pbOutData;
	delete []pbInData;

	return 0;

}




int CParserPostMsg::SOF_EncryptDataDW2()
{
	std::string szSymmKey = m_inRoot["SymmKey"].asString();
	std::string szIndata = m_inRoot["Indata"].asString();
	std::string szOutData;

	if (!SOF_EncryptDataDWLoc(szSymmKey,szIndata,szOutData))
	{
		Json::Value jsVal;

		jsVal["EncryptData"] = szOutData;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}

	return 1;

}



int CParserPostMsg::SOF_EncryptDataDW()//---改为本地加密，该函数废弃
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}
	std::string szSymmKey = m_inRoot["SymmKey"].asString();
	std::string szIndata = m_inRoot["Indata"].asString();

	ns1__SOF_USCOREEncryptData sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.inData = &szIndata;
	sofRequest.key = &szSymmKey;

	int nReturn_ = soapSender::SOF_EncryptData(sofRequest, szResp);
	if (0 == nReturn_)
	{

		Json::Value jsVal;
		
		jsVal["EncryptData"] = szResp;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;

	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_EncryptData failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		LOG_ERROR(strInfo);
		DealwithError("Encrypt data failed");
		return 1;
	}


}
int CParserPostMsg::SOF_DecryptDataDWLoc(std::string szSymmKey,std::string szIndata,std::string& szOutdata)
{
	if (szSymmKey.length() !=16)
	{
		DealwithError("密钥长度必须是16位");
		return 1;
	}

	DWORD dwRet = 0, dwInDataLen = 0, dwOutDataLen = 0;
	HANDLE hKey = NULL;
	DWORD dwBaseLen = 0;
	BYTE *bOutData = NULL, *bBase = NULL;




	//得到解密密钥
	BYTE bKey[0x40] = {0};
	memcpy(bKey, szSymmKey.c_str(), 16);

	//得到base64解密后的数据
	dwInDataLen = szIndata.length();
	bBase = new BYTE[dwInDataLen];
	memset(bBase, 0x00, dwInDataLen);
	dwBaseLen = Base64Decode(bBase,szIndata.c_str());

	//得到第一个证书
	ReadCertInfo* pRCI =GetCertInfo("",TRUE);
	if (NULL == pRCI)
	{
		DealwithError("no find cert");
		return 1;
	}

	CReadUKey* pReadUKey = (CReadUKey*)pRCI->m_pReadUkey;
	dwRet = pReadUKey->m_PSKF_SetSymmKey(pRCI->m_hDev, bKey,m_nEncryptMethod, &hKey);
	if (dwRet)
	{
		DealwithError("SKF_SetSymmKey failed");
		delete []bBase;
		return dwRet;
	}

	BLOCKCIPHERPARAM DencryptParam;
	memset((char *)&DencryptParam,0x00,sizeof(BLOCKCIPHERPARAM));
	dwRet = pReadUKey->m_PSKF_DecryptInit(hKey,DencryptParam);
	if (dwRet)
	{
		DealwithError("m_PSKF_DecryptInit failed");
		delete []bBase;
		return dwRet;
	}

	dwRet = pReadUKey->m_PSKF_Decrypt(hKey, bBase, dwBaseLen, bOutData, &dwOutDataLen);
	if (dwRet)
	{
		DealwithError("m_PSKF_Decrypt failed");
		delete []bBase;
		return dwRet;
	}


	bOutData = new BYTE[dwOutDataLen+1];
	memset(bOutData, 0x00, dwOutDataLen+1);
	dwRet = pReadUKey->m_PSKF_Decrypt(hKey, bBase, dwBaseLen, bOutData, &dwOutDataLen);
	if (dwRet)
	{
		DealwithError("m_PSKF_Decrypt failed");
		delete []bBase;
		delete []bOutData;
		return dwRet;
	}

	szOutdata = (char*)bOutData;
	delete []bBase;
	delete []bOutData;
	return 0;


}

int CParserPostMsg::SOF_DecryptFileDWLoc(std::string szSymmKey,std::string szIndata,std::string szInFile)
{
	if (szSymmKey.length() !=16)
	{
		DealwithError("密钥长度必须是16位");
		return 1;
	}

	DWORD dwRet = 0, dwInDataLen = 0, dwOutDataLen = 0;
	HANDLE hKey = NULL;
	DWORD dwBaseLen = 0;
	BYTE *bOutData = NULL, *bBase = NULL;




	//得到解密密钥
	BYTE bKey[0x40] = {0};
	memcpy(bKey, szSymmKey.c_str(), 16);

	//得到base64解密后的数据
	dwInDataLen = szIndata.length();
	bBase = new BYTE[dwInDataLen];
	memset(bBase, 0x00, dwInDataLen);
	dwBaseLen = Base64Decode(bBase,szIndata.c_str());

	//得到第一个证书
	ReadCertInfo* pRCI =GetCertInfo("",TRUE);
	if (NULL == pRCI)
	{
		DealwithError("no find cert");
		return 1;
	}

	CReadUKey* pReadUKey = (CReadUKey*)pRCI->m_pReadUkey;
	dwRet = pReadUKey->m_PSKF_SetSymmKey(pRCI->m_hDev, bKey,m_nEncryptMethod, &hKey);
	if (dwRet)
	{
		DealwithError("SKF_SetSymmKey failed");
		delete []bBase;
		return dwRet;
	}

	BLOCKCIPHERPARAM DencryptParam;
	memset((char *)&DencryptParam,0x00,sizeof(BLOCKCIPHERPARAM));
	dwRet = pReadUKey->m_PSKF_DecryptInit(hKey,DencryptParam);
	if (dwRet)
	{
		DealwithError("m_PSKF_DecryptInit failed");
		delete []bBase;
		return dwRet;
	}

	dwRet = pReadUKey->m_PSKF_Decrypt(hKey, bBase, dwBaseLen, bOutData, &dwOutDataLen);
	if (dwRet)
	{
		DealwithError("m_PSKF_Decrypt failed");
		delete []bBase;
		return dwRet;
	}


	bOutData = new BYTE[dwOutDataLen+1];
	memset(bOutData, 0x00, dwOutDataLen+1);
	dwRet = pReadUKey->m_PSKF_Decrypt(hKey, bBase, dwBaseLen, bOutData, &dwOutDataLen);
	if (dwRet)
	{
		DealwithError("m_PSKF_Decrypt failed");
		delete []bBase;
		delete []bOutData;
		return dwRet;
	}

	FILE    *fp;
	fp=fopen(szInFile.c_str() ,"wb+");
	if(!fp)
	{
		DealwithError("m_PSKF_Decrypt failed");
		delete []bBase;
		delete []bOutData;
		return -1;
	}

	long lIndex = dwOutDataLen-1;

	while (*(bOutData+lIndex) == 0)
	{
		lIndex--;
	}

	dwOutDataLen = lIndex+1;
	//dwOutDataLen = 13778;
	int nNum = 0;
	for (int i=0; i< dwOutDataLen;i = i+1024)
	{
		if (i+1024 >dwOutDataLen)
		{
			int len = fwrite(bOutData+i, 1,dwOutDataLen-i ,fp);
		}
		else
		{
			int len = fwrite(bOutData+i, 1,1024 ,fp);
		}

	nNum+=200;
		
	}


	//BYTE* bOutData2 = new BYTE[5];
	//memset(bOutData2, 0x00, 5);
	//memcpy(bOutData2,"qwer",4);
	//int dwOutDataLen2 = 4;
	//int len = fwrite(bOutData2, 1,dwOutDataLen2 ,fp);
	//Sleep(2000);
	//fflush(fp);
	fclose(fp);

	//Sleep(nNum);	

	Json::Value jsVal;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());


	delete []bBase;
	delete []bOutData;
	return 0;


}


int CParserPostMsg::SOF_DecryptDataDW2()
{
	std::string szSymmKey = m_inRoot["SymmKey"].asString();
	std::string szIndata = m_inRoot["Indata"].asString();
	std::string szOutData;

	if (!SOF_DecryptDataDWLoc(szSymmKey,szIndata,szOutData))
	{
		Json::Value jsVal;

		jsVal["DecryptData"] = szOutData;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}

	return 1;

}

int CParserPostMsg::SOF_DecryptDataDW()//---改为本地解密，该函数废弃
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}
	std::string szSymmKey = m_inRoot["SymmKey"].asString();
	std::string szIndata = m_inRoot["Indata"].asString();

	ns1__SOF_USCOREDecryptData sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.inData = &szIndata;
	sofRequest.key = &szSymmKey;

	int nReturn_ = soapSender::SOF_DecryptData(sofRequest, szResp);
	if (0 == nReturn_)
	{
		Json::Value jsVal;
		
		jsVal["DecryptData"] = szResp;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_DecryptData failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		LOG_ERROR(strInfo);
		DealwithError("Decrypt data failed");
		return 0;
	}
	
}

int CParserPostMsg::SOF_EncryptFileDW2()
{

	std::string szSymmKey = m_inRoot["SymmKey"].asString();
	std::string szInFile = m_inRoot["InFile"].asString();
	std::string szOutFile = m_inRoot["OutFile"].asString();

	//得到待加密文件
//	std::string szInData;
	m_btBuf = NULL;
	m_lLen =0;
	if (ReadByteFileInfo(szInFile))
	{
		DealwithError("file is not exist");
		return 1;
	}


	/*FILE    *fp;
	fp=fopen("d:\\12.doc" ,"wb+");
	for (int i=0; i< m_lLen;i = i+1024)
	{
		if (i+1024 >m_lLen)
		{
			int len = fwrite(m_btBuf+i, 1,m_lLen-i ,fp);
		}
		else
		{
			int len = fwrite(m_btBuf+i, 1,1024 ,fp);
		}

	}
	fclose(fp);*/

	std::string szOutData;

	if (!SOF_EncryptFileDWLoc(szSymmKey,m_btBuf,m_lLen,szOutFile))
	{
		if (NULL != m_btBuf)
		{
			delete []m_btBuf;
		}
		
		return 0;
	}

	if (NULL != m_btBuf)
	{
		delete []m_btBuf;
	}

	return 1;
	
}

int CParserPostMsg::SOF_EncryptFileDW()//---改为本地加密，该函数废弃
{

	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}
	std::string szSymmKey = m_inRoot["SymmKey"].asString();
	std::string szInFile = m_inRoot["InFile"].asString();
	std::string szOutFile = m_inRoot["OutFile"].asString();

	//得到待加密文件
	std::string szInData;
	if (ReadFileInfo(szInFile,szInData))
	{
		DealwithError("file is not exist");
		return 1;
	}

	ns1__SOF_USCOREEncryptData sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.inData = &szInData;
	sofRequest.key = &szSymmKey;

	int nReturn_ = soapSender::SOF_EncryptData(sofRequest, szResp);
	if (0 != nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_EncryptData failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		LOG_ERROR(strInfo);
		DealwithError("Encrypt File failed");
		return 1;
	}

	//生成新的文件，规则在原有文件名上加上年月日时分秒
	std::string szNewPath = szOutFile;
	if (WriteFileInfo(szInFile, szResp, szNewPath))
	{
		DealwithError("file name format is error");
		return 1;
	}



	Json::Value jsVal;
	
	//jsVal["OutFile"] = szNewPath;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());
	return 0;
}

int CParserPostMsg::SOF_DecryptFileDW2()
{
	std::string szSymmKey = m_inRoot["SymmKey"].asString();
	std::string szInFile = m_inRoot["InFile"].asString();
	std::string szOutFile = m_inRoot["OutFile"].asString();

	//得到待加密文件
	std::string szInData;
	if (ReadFileInfo(szInFile,szInData))
	{
		DealwithError("file is not exist");
		return 1;
	}

	std::string szOutData;
	if (!SOF_DecryptFileDWLoc(szSymmKey,szInData,szOutFile))
	{
		////生成新的文件，规则在原有文件名上加上年月日时分秒
		//std::string szNewPath = szOutFile;
		//if (WriteFileInfo(szInFile, szOutData, szNewPath))
		//{
		//	DealwithError("file name format is error");
		//	return 1;
		//}


		//Json::Value jsVal;
		//jsVal["resultCode"] = "0";
		//SendResp(jsVal.toStyledString());
		return 0;
	}

	return 1;


	
}
int CParserPostMsg::SOF_DecryptFileDW()//---改为本地解密，该函数废弃
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}
	std::string szSymmKey = m_inRoot["SymmKey"].asString();
	std::string szInFile = m_inRoot["InFile"].asString();
	std::string szOutFile = m_inRoot["OutFile"].asString();

	//得到待加密文件
	std::string szInData;
	if (ReadFileInfo(szInFile,szInData))
	{
		DealwithError("file is not exist");
		return 1;
	}



	ns1__SOF_USCOREDecryptData sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.inData = &szInData;
	sofRequest.key = &szSymmKey;

	int nReturn_ = soapSender::SOF_DecryptData(sofRequest, szResp);
	if (0 != nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_DecryptData failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		LOG_ERROR(strInfo);
		DealwithError("Decrypt File failed");
		return 1;	
	}

	//生成新的文件，规则在原有文件名上加上年月日时分秒
	std::string szNewPath = szOutFile;
	if (WriteFileInfo(szInFile, szResp, szNewPath))
	{
		DealwithError("file name format is error");
		return 1;
	}


	Json::Value jsVal;
	
	//jsVal["OutFile"] = szNewPath;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());
	return 0;
}

int CParserPostMsg::SOF_PubKeyEncryptDW()
{
	std::string szCert = m_inRoot["Cert"].asString();
	std::string szInData = m_inRoot["InData"].asString();
	std::string szOutData;

	//base64 解码
	int nLen = szCert.length();
	unsigned char* byDest = new unsigned char[nLen];
	memset(byDest,0,nLen);
	int nOutLen = Base64Decode(byDest,szCert.c_str());


	ULONG rv = 0;
	std::string szbase64OutData;
	CCSPCertificate cspCert;
	cspCert._DecodeX509Cert(byDest, nOutLen);
	char lpValue[500] = {0};
	ULONG ulLen = 500;
	ULONG m_ulType = 0; 
	cspCert.get_SN(lpValue,&ulLen);
	cspCert.get_KeyType(&m_ulType);

	ReadCertInfo* pRCI = GetCertInfo(lpValue);
	if (NULL == pRCI)
	{
		DealwithError("no find cert");
		return 1;
	}

	CReadUKey* pReadUKey = (CReadUKey*)pRCI->m_pReadUkey;
	pReadUKey->m_hDev = pRCI->m_hDev;
	pReadUKey->m_hApp = pRCI->m_hApp;
	pReadUKey->m_hAContainer = pRCI->m_hAContainer;
	g_readUKey = pReadUKey;
	BYTE* pbOutData = NULL;
	ULONG pdwOutDataLen = 0;


	if (m_ulType == CERT_KEY_ALG_RSA)
	{

		RSAPUBLICKEYBLOB pPubKey;
		ULONG ulPubKeyLen = 0;
		ulPubKeyLen = sizeof(pPubKey);
		rv = pReadUKey->m_PSKF_ExportPublicKey(pRCI->m_hAContainer,FALSE,(unsigned char *)&pPubKey,&ulPubKeyLen);
		if(rv != SAR_OK)
		{
			DealwithError("m_PSKF_ExportPublicKey failed");
			return -1;
		}

		rv = pReadUKey->RSAPubKeyEncryptEx(pRCI->m_hDev,&pPubKey,szInData, pbOutData, &pdwOutDataLen);
		if(rv != SAR_OK)
		{
			DealwithError("RSAPubKeyEncryptEx failed");
			return -1;
		}

		Base64 bs64;
		szOutData = bs64.base64_encode((unsigned char*)pbOutData, pdwOutDataLen);
		delete[] pbOutData;


	}
	else
	{
		ECCPUBLICKEYBLOB pEccSignKey = {0};
		ULONG ulEccPubKeyLen = sizeof(ECCPUBLICKEYBLOB);


		rv = pReadUKey->m_PSKF_ExportPublicKey(pRCI->m_hAContainer,FALSE,(unsigned char *)&pEccSignKey,&ulEccPubKeyLen);

		if(rv != SAR_OK)
		{
			DealwithError("m_PSKF_ExportPublicKey failed");
			return -1;
		}


		int nLen = szInData.length();
		rv = pReadUKey->m_PSKF_ExtECCEncrypt(pRCI->m_hDev,(ECCPUBLICKEYBLOB*)&pEccSignKey,(BYTE*)szInData.c_str(), nLen, &pEccCipherBlob);
		if(rv != SAR_OK)
		{
			DealwithError("m_PSKF_ExtECCEncrypt failed");
			return -1;
		}

		int nSize = sizeof(pEccCipherBlob);
		BYTE* pEccCipherBlob2 = new BYTE[nSize+pEccCipherBlob.CipherLen];
		memset(pEccCipherBlob2,0,nSize+pEccCipherBlob.CipherLen);
		memcpy_s((void*)pEccCipherBlob2,nSize+pEccCipherBlob.CipherLen,(void*)(&pEccCipherBlob),nSize+pEccCipherBlob.CipherLen);
	

		Base64 bs64;
		szOutData = bs64.base64_encode((unsigned char*)pEccCipherBlob2, nSize+pEccCipherBlob.CipherLen);
		delete[] pEccCipherBlob2;
	}

	Json::Value jsVal;

	jsVal["EncryptData"] = szOutData;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());
	return 0;


	


	//ns1__SOF_USCOREPubKeyEncrypt sofRequest;
	//std::string szResp;

	//std::string szToken("9877654433");
	////sofRequest.tokenId = &szToken;
	//sofRequest.base64EncodeCert = &szCert;
	//sofRequest.inData =&szInData;

	//LOG_INFO("SOF_PubKeyEncrypt:sofRequest.base64EncodeCert=\r\n%s\r\nsofRequest.inData=%s",
	//	sofRequest.base64EncodeCert->c_str(),
	//	sofRequest.inData->c_str());

	//int nReturn_ = soapSender::SOF_PubKeyEncrypt(sofRequest, szResp);
	//if (0 == nReturn_)
	//{
	//	Json::Value jsVal;
	//	
	//	jsVal["EncryptData"] = szResp;
	//	jsVal["resultCode"] = "0";
	//	SendResp(jsVal.toStyledString());
	//	return 0;
	//}
	//else
	//{
	//	CString strInfo;
	//	strInfo.Format("SOF_PubKeyEncrypt failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
	//	LOG_ERROR(strInfo);
	//	DealwithError("Pubkey encrypt data failed");
	//	return 1;
	//}

}


int CParserPostMsg::SOF_PriKeyDecryptDW()
{
	std::string szCertId = m_inRoot["CertID"].asString();
	std::string szDecryptData = m_inRoot["InData"].asString();


	//得到证书信息
	ReadCertInfo* pRCI = GetCertInfo(szCertId);
	if (NULL == pRCI)
	{
		DealwithError("no find cert");
		return 1;
	}

	CReadUKey* pReadUKey = (CReadUKey*)pRCI->m_pReadUkey;
	pReadUKey->m_hDev = pRCI->m_hDev;
	pReadUKey->m_hApp = pRCI->m_hApp;
	pReadUKey->m_hAContainer = pRCI->m_hAContainer;
	g_readUKey = pReadUKey;
	BYTE* pbOutData = NULL;
	ULONG pdwOutDataLen = 0;
	BYTE* pbOutData2 = NULL;
	ULONG pdwOutDataLen2 = 0;

	


	ULONG rv = 0;
	std::string szbase64OutData;
	CCSPCertificate cspCert;
	cspCert._DecodeX509Cert(pRCI->m_pCert, pRCI->m_ulCertLen);
	cspCert.get_KeyType(&(pReadUKey->m_ulType));
	if (pReadUKey->m_ulType == CERT_KEY_ALG_RSA)
	{

		if (0)//test
		{
			RSAPUBLICKEYBLOB pPubKey;
			ULONG ulPubKeyLen = 0;
			ulPubKeyLen = sizeof(pPubKey);
			rv = pReadUKey->m_PSKF_ExportPublicKey(pRCI->m_hAContainer,FALSE,(unsigned char *)&pPubKey,&ulPubKeyLen);
			if(rv != SAR_OK)
			{
				DealwithError("no find cert");
				return -1;
			}

			rv = pReadUKey->RSAPubKeyEncryptEx(pRCI->m_hDev,&pPubKey,szDecryptData, pbOutData, &pdwOutDataLen);
		}
		else
		{
			int len = szDecryptData.length();
			pbOutData = new unsigned char[len];
			memset(pbOutData, 0, len);
			pdwOutDataLen = Base64Decode(pbOutData, szDecryptData.c_str());
		}
		


		CPinDlg dlg;
		if (IDOK == dlg.DoModal())
		{
			
			rv = pReadUKey->RSAPriKeyDecryptEx2(pRCI->m_hAContainer,pbOutData,pdwOutDataLen, pbOutData2, &pdwOutDataLen2);

			free(pbOutData);

		}


	}
	else//
	{
		CPinDlg dlg;
		if (IDOK == dlg.DoModal())
		{

			std::string szInfo("1234567890qwertyuiopasdfghjklz12",32);
			LOG_INFO("m_PSKF_ECCDecrypt pbOutData=%s",szInfo.c_str());

			
			if (0)//test
			{
				szDecryptData = "1234567890qwertyuiopasdfghjklz12";
				
				ECCPUBLICKEYBLOB pEccSignKey = {0};
				ULONG ulEccPubKeyLen = sizeof(ECCPUBLICKEYBLOB);


				rv = pReadUKey->m_PSKF_ExportPublicKey(pRCI->m_hAContainer,FALSE,(unsigned char *)&pEccSignKey,&ulEccPubKeyLen);

				if(rv != SAR_OK)
				{
					DealwithError("no find cert");
					return -1;
				}


				int nLen = szDecryptData.length();

				rv = pReadUKey->m_PSKF_ExtECCEncrypt(pRCI->m_hDev,(ECCPUBLICKEYBLOB*)&pEccSignKey,(BYTE*)szDecryptData.c_str(), nLen, &pEccCipherBlob);

				int nSize = sizeof(pEccCipherBlob);

				BYTE* pEccCipherBlob2 = new BYTE[nSize+32];
				memset(pEccCipherBlob2,0,nSize+32);
				memcpy_s((void*)pEccCipherBlob2,nSize+32,(void*)(&pEccCipherBlob),nSize+pEccCipherBlob.CipherLen);
				rv = pReadUKey->ECCDecryptEx2(pRCI->m_hAContainer,(ECCCIPHERBLOB*)pEccCipherBlob2, pbOutData2, &pdwOutDataLen2);


				Base64 bs64;
				std::string szTMP1 = bs64.base64_encode((unsigned char*)pEccCipherBlob2, nSize+pEccCipherBlob.CipherLen);
				LOG_INFO("m_PSKF_ECCDecrypt pbOutData=%s",szInfo.c_str());
			}
			else
			{
				int len = szDecryptData.length();
				pbOutData = new unsigned char[len];
				memset(pbOutData, 0, len);
				pdwOutDataLen = Base64Decode(pbOutData, szDecryptData.c_str());
			}

			rv = pReadUKey->ECCDecryptEx2(pRCI->m_hAContainer,(ECCCIPHERBLOB*)pbOutData, pbOutData2, &pdwOutDataLen2);

			free(pbOutData);

		}

	}

	if (rv)
	{
		CString strInfo;
		strInfo.Format("SOF_PriKeyDecrypt failed! ");
		LOG_ERROR(strInfo);
		DealwithError("PriKeyDecrypt data failed");
		if (NULL != pbOutData2)
		{
			free(pbOutData2);
		}
		return 1;
	}
	else
	{
		Json::Value jsVal;
		jsVal["DecryptData"] = (char*)pbOutData2;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		if (NULL != pbOutData2)
		{
			free(pbOutData2);
		}
		return 0;
	}


	

	//CCSPCertificate cspCert;
	//if (cspCert.EnumCerts(FALSE,szCertId))
	//{
	//	DealwithError("no find cert");
	//	return 1;
	//}


	//std::string szData;

	//if (cspCert.gtDecryptData(szDecryptData,szData))
	//{
	//	CString strInfo;
	//	strInfo.Format("SOF_PriKeyDecrypt failed! ");
	//	LOG_ERROR(strInfo);
	//	DealwithError("PriKeyDecrypt data failed");
	//	return 1;
	//}
	//else
	//{
	//	Json::Value jsVal;

	//	jsVal["DecryptData"] = szData;
	//	jsVal["resultCode"] = "0";
	//	SendResp(jsVal.toStyledString());
	//	return 0;
	//}
	//
	
}
int CParserPostMsg::SOF_SignDataByP7DW()
{
	std::string szCertId = m_inRoot["CertID"].asString();
	std::string szInData = m_inRoot["InData"].asString();

	//std::string szCertId = "2017051102963615";
	//std::string szInData = "qwertyuiop1234567890asdfghjkl132";


	CCSPCertificate cspCert;
	if (cspCert.EnumCerts(TRUE,szCertId))
	{
		DealwithError("no find cert");
		return 1;
	}

	BYTE  *pbSignedMessageBlob = NULL;
	if (1)
	{

		CRYPT_SIGN_MESSAGE_PARA  SigParams;
		DWORD cbSignedMessageBlob;

		// Create the MessageArray and the MessageSizeArray.
		BYTE* pbMessage = (BYTE*) szInData.c_str();
		const BYTE* MessageArray[] = {pbMessage};
		DWORD MessageSizeArray[1];
		MessageSizeArray[0] = szInData.length()*2;

		// Initialize the signature structure.
		SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
		SigParams.dwMsgEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
		SigParams.pSigningCert = cspCert.m_pCertContext;
		SigParams.HashAlgorithm.pszObjId = szOID_OIWSEC_sha1 ;
		SigParams.HashAlgorithm.Parameters.pbData = NULL;
		SigParams.HashAlgorithm.Parameters.cbData = 0;
		SigParams.cMsgCert = 1;
		SigParams.rgpMsgCert = &cspCert.m_pCertContext;
		SigParams.cAuthAttr = 0;
		SigParams.dwInnerContentType = 0;
		SigParams.rgpMsgCrl = NULL;
		SigParams.cMsgCrl = 0;
		SigParams.rgUnauthAttr = NULL;
		SigParams.cUnauthAttr = 0;
		SigParams.dwFlags = 0; 
		SigParams.pvHashAuxInfo = NULL;
		SigParams.rgAuthAttr = NULL;

		// With two calls to CryptSignMessage, sign the message.
		// First, get the size of the output signed BLOB.
		if(!CryptSignMessage(
			&SigParams,            // Signature parameters
			FALSE,             // detached?
			1,                     // Number of messages
			MessageArray,          // Messages to be signed
			MessageSizeArray,      // Size of messages
			NULL,                  // Buffer for signed message
			&cbSignedMessageBlob)) // Size of buffer
		{
			LOG_ERROR("CryptSignMessage failed");
			DealwithError("CryptSignMessage failed");
			return 1;

		}

		//-------------------------------------------------------------------
		// Allocate memory for the signed BLOB.
		if(!(pbSignedMessageBlob = 
			(BYTE*)malloc(cbSignedMessageBlob)))
		{
			LOG_ERROR("malloc failed");
			DealwithError("malloc failed");
			return 1;
		}

		//-------------------------------------------------------------------
		// Get the SignedMessageBlob.
		if(!CryptSignMessage(
			&SigParams,            // Signature parameters
			FALSE,             // detached?
			1,                     // Number of messages
			MessageArray,          // Messages to be signed
			MessageSizeArray,      // Size of messages
			pbSignedMessageBlob,   // Buffer for signed message
			&cbSignedMessageBlob)) // Size of buffer
		{
			LOG_ERROR("CryptSignMessage failed");
			DealwithError("CryptSignMessage failed");
			if(pbSignedMessageBlob)
				free(pbSignedMessageBlob);
			return 1;
		}	

		char* szBuf = new char[cbSignedMessageBlob*2];
		memset(szBuf, 0, cbSignedMessageBlob*2);
		int nbase64 = Base64Encode(szBuf,pbSignedMessageBlob,cbSignedMessageBlob);
		std::string szResp = szBuf;
		delete szBuf;

		Json::Value jsVal;

		jsVal["SignData"] = szResp;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		if(pbSignedMessageBlob)
			free(pbSignedMessageBlob);
		return 0;
	}
}
int CParserPostMsg::SOF_VerifySignedDataByP7DW()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	std::string szP7Data = m_inRoot["P7Data"].asString();
	std::string szResp;
	int nReturn_ = -1;
	int nResp = 0;
	BOOL bResp = FALSE;


	if (0 == m_strUrl.Compare("VerifySignedDataByP7"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_VERIFYSIGNEDDATABYP7,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			nReturn_ =m_PSDM.DealWithRecvMsg("result",szResp);
			if (0 == nReturn_)
			{
				if (0 == szResp.compare("0"))
				{
					bResp = TRUE;
				}
				else
				{
					bResp = FALSE;
				}
			}
		}
	}
	else
	{
		ns1__SOF_USCOREVerifySignedDataByP7 sofRequest;
		sofRequest.pkcs7SignData =&szP7Data;
		LOG_INFO("SOF_VerifySignedDataByP7:sofRequest.pkcs7SignData=%s",sofRequest.pkcs7SignData->c_str());
		nReturn_ = soapSender::SOF_VerifySignedDataByP7(sofRequest, bResp);
	}

	if (bResp)
	{
		Json::Value jsVal;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_VerifySignedDataByP7 failed! nReturn_=%d,bResp=%d",nReturn_, bResp);
		LOG_ERROR(strInfo);
		DealwithError("VerifySignedDataByP7 data failed");
		return 1;
	}
}
int CParserPostMsg::SOF_GetP7SignDataInfoDW()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	if (!m_inRoot["type"].isInt())
	{
		DealwithError("interface format is error");
		return 1;
	}

	std::string szP7Data = m_inRoot["P7Data"].asString();
	int nType = m_inRoot["type"].asInt();
	std::string szResp;
	int nReturn_ = -1;


	if (0 == m_strUrl.Compare("GetP7SignDataInfo"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_GETP7SIGNDATAINFO,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			std::string szTmp = szResp;
			nReturn_ =m_PSDM.DealWithRecvMsg("resultCode",szResp);
			if (0 == nReturn_ && 0 == szResp.compare("0"))
			{
				szResp = szTmp;
				nReturn_ =m_PSDM.DealWithRecvMsg("resultData",szResp);
			}
			else
			{
				nReturn_ =1;
			}
		}
	}
	else
	{
		ns1__SOF_USCOREGetP7SignDataInfo sofRequest;
		sofRequest.pkcs7SignData =&szP7Data;
		sofRequest.type =nType;
		LOG_INFO("SOF_GetP7SignDataInfo:sofRequest.pkcs7SignData=%s,sofRequest.type=%d",sofRequest.pkcs7SignData->c_str(),
			sofRequest.type);
		nReturn_ = soapSender::SOF_GetP7SignDataInfo(sofRequest, szResp);
	}

	
	if (0 == nReturn_)
	{

		Json::Value jsVal;
		
		jsVal["Data"] = szResp;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_GetP7SignDataInfo failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		LOG_ERROR(strInfo);
		DealwithError("GetP7SignDataInfo data failed");
		return 1;
	}
}
std::string g_szTest;
int CParserPostMsg::SOF_SignDataXMLDW()
{
	std::string szCertId = m_inRoot["CertID"].asString();
	std::string szInData = m_inRoot["InData"].asString();

	std::string szOutSignData;
	std::string szhashData;
	 ReadCertInfo* pOutRCI = NULL;
	if (0 == SOF_SignDataDW(szCertId,szInData,szOutSignData,szhashData,pOutRCI))
	{
		std::string szCert;
		Base64 bs64;
		szCert = bs64.B64_Encode(pOutRCI->m_pCert,pOutRCI->m_ulCertLen);

		CXMLDOMParser xmlPas;
		std::string szXMLFile;
		if (g_readUKey->m_ulType == CERT_KEY_ALG_RSA)
		{
			if (SGD_SHA1 == m_nHashType)
			{
				szXMLFile = g_strExePath+"\\config\\sha1_rsa.xml";
			}
			else if (SGD_SHA256 == m_nHashType)
			{
				szXMLFile = g_strExePath+"\\config\\sha256_rsa.xml";
			}
			else if (SGD_SM3 == m_nHashType)
			{
				szXMLFile = g_strExePath+"\\config\\sm3_rsa.xml";
			}
		}
		else
		{
			szXMLFile = g_strExePath+"\\config\\sm3_sm2.xml";
		}
		
		
		std::string szXML;
		if (xmlPas.MakeSignXML(szXMLFile,szInData,szOutSignData,szhashData,szCert,szXML))
		{
			//szXML = "<?xml version=\"1.0\"?>\r\n"+szXML;
			//g_szTest = szXML;
			//SOF_VerifySignedDataXMLDW();

			Json::Value jsVal;
			jsVal["SignData"] = szXML;
			jsVal["resultCode"] = "0";
			SendResp(jsVal.toStyledString());
			return 0;
		}

		DealwithError("SignDataXML data failed");
		return 1;

		
	}
	else
	{
		return 1;
	}


	//ns1__SOF_USCORESignDataXML sofRequest;
	//std::string szResp;

	//std::string szToken("9877654433");
	////sofRequest.tokenId = &szToken;
	//sofRequest.inData =&szInData;

	//LOG_INFO("SOF_SignDataXML:sofRequest.inData=\r\n%s",sofRequest.inData->c_str());

	//int nReturn_ = soapSender::SOF_SignDataXML(sofRequest, szResp);
	//if (0 == nReturn_)
	//{
	//	Json::Value jsVal;
	//	
	//	jsVal["SignData"] = szResp;
	//	jsVal["resultCode"] = "0";
	//	SendResp(jsVal.toStyledString());
	//	return 0;
	//}
	//else
	//{
	//	CString strInfo;
	//	strInfo.Format("SOF_SignDataXML failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
	//	LOG_ERROR(strInfo);
	//	DealwithError("SignDataXML data failed");
	//	return 1;
	//}
}

int CParserPostMsg::SOF_VerifySignedDataXMLDW()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	std::string szInData = m_inRoot["InData"].asString();
	std::string szResp;
	int nReturn_ = -1;
	int nResp = 0;
	BOOL bResp = FALSE;


	if (0 == m_strUrl.Compare("VerifySignedDataXML"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_VERIFYSIGNEDDATAXML,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			nReturn_ =m_PSDM.DealWithRecvMsg("result",szResp);
			if (0 == nReturn_)
			{
				if (0 == szResp.compare("0"))
				{
					bResp = TRUE;
				}
				else
				{
					bResp = FALSE;
				}
			}
		}
	}
	else
	{
		ns1__SOF_USCOREVerifySignedDataXML sofRequest;
		sofRequest.inData =&szInData;
		LOG_INFO("SOF_VerifySignedDataXML:sofRequest.inData=%s", sofRequest.inData->c_str());
		nReturn_ = soapSender::SOF_VerifySignedDataXML(sofRequest, bResp);
	}

	
	if (bResp)
	{
		Json::Value jsVal;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_VerifySignedDataXML failed! nReturn_=%d,bResp=%d",nReturn_, bResp);
		LOG_ERROR(strInfo);
		DealwithError("VerifySignedDataXML data failed");
		return 1;
	}
}
int CParserPostMsg::SOF_GetXMLSignatureInfoDW()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}
	if (!m_inRoot["type"].isInt())
	{
		DealwithError("interface format is error");
		return 1;
	}

	std::string szXMLSignedData = m_inRoot["XMLSignedData"].asString();
	int nType = m_inRoot["type"].asInt();
	std::string szResp;
	int nReturn_ = -1;

	if (0 == m_strUrl.Compare("GetXMLSignatureInfo"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_GETXMLSIGNTUREINFO,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			std::string szTmp = szResp;
			nReturn_ =m_PSDM.DealWithRecvMsg("resultCode",szResp);
			if (0 == nReturn_ && 0 == szResp.compare("0"))
			{
				szResp = szTmp;
				nReturn_ =m_PSDM.DealWithRecvMsg("resultData",szResp);
			}
			else
			{
				nReturn_ =1;
			}
		}
	}
	else
	{
		//ReadFileInfo("D:\\x.txt",szXMLSignedData);
		ns1__SOF_USCOREGetXMLSignatureInfo sofRequest;
		sofRequest.XMLSignedData =&szXMLSignedData;
		sofRequest.type = nType;
		LOG_INFO("SOF_GetXMLSignatureInfo:sofRequest.XMLSignedData=%s,sofRequest.type=%d",sofRequest.XMLSignedData->c_str(),
			sofRequest.type);
		nReturn_ = soapSender::SOF_GetXMLSignatureInfo(sofRequest, szResp);
	}

	
	if (0 == nReturn_)
	{
		Json::Value jsVal;
		
		jsVal["Data"] = szResp;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_GetXMLSignatureInfo failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		LOG_ERROR(strInfo);
		DealwithError("GetXMLSignatureInfo data failed");
		return 1;
	}
}
int CParserPostMsg::SOF_CheckSupportDW()
{
	Json::Value jsVal;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());
	return 0;
}

int CParserPostMsg::SOF_GenRandomDW()
{
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}

	if (!m_inRoot["len"].isInt())
	{
		DealwithError("interface format is error");
		return 1;
	}

	int nLen = m_inRoot["len"].asInt();


	

	//ReadCertInfo* pRCI =GetCertInfo("",TRUE);
	//if (NULL == pRCI)
	//{
	//	DealwithError("no find cert");
	//	return 1;
	//}

	//CReadUKey* pReadUKey = (CReadUKey*)pRCI->m_pReadUkey;

	//BYTE* byBuf = new BYTE(nLen+1);
	//memset(byBuf,0,nLen+1);

	//ULONG nRet = pReadUKey->m_PSKF_GenRandom(pRCI->m_hDev,byBuf,nLen);
	//if (0 == nRet)
	//{
	//	Json::Value jsVal;

	//	jsVal["Base64Random"] = (char*)byBuf;
	//	jsVal["resultCode"] = "0";
	//	SendResp(jsVal.toStyledString());
	//	return 0;
	//}
	//else
	//{
	//	CString strInfo;
	//	strInfo.Format("m_PSKF_GenRandom failed! nReturn_=%d,szResp=%s",nRet,byBuf);
	//	LOG_ERROR(strInfo);
	//	DealwithError("GenRandom data failed");
	//	return 1;
	//}

	std::string szResp;
	int nReturn_ = -1;

	if (0 == m_strUrl.Compare("GenRandom"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_GENRANDOM,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			std::string szTmp = szResp;
			nReturn_ =m_PSDM.DealWithRecvMsg("resultMsg",szResp);
			if (0 == szResp.compare("success"))
			{
				szResp = szTmp;
				nReturn_ =m_PSDM.DealWithRecvMsg("randombase64",szResp);
			}
			else
			{
				nReturn_ = 1;
			}
			
		}
	}
	else
	{
		ns1__SOF_USCOREGenRandom sofRequest;
		sofRequest.len= nLen;
		LOG_INFO("SOF_USCOREGenRandom:len=%d", sofRequest.len);
		nReturn_ = soapSender::SOF_USCOREGenRandom(sofRequest, szResp);
	}



	
	if (0 == nReturn_)
	{
		Json::Value jsVal;
		
		jsVal["Base64Random"] = szResp;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_USCOREGenRandom failed! nReturn_=%d,szResp=%s",nReturn_,szResp.c_str());
		LOG_ERROR(strInfo);
		DealwithError("GenRandom data failed");
		return 1;
	}

	return 1;
}

CString GetFilePath(CString csFilePath)  
{  
	int nPos = csFilePath.ReverseFind('\\'); // 文件路径，以'\'斜杠分隔的路径  
	if (-1 == nPos)
	{
		return "";
	}
	CString csFileFullName;  
	csFileFullName = csFilePath.Left(nPos+1); // 获取文件全名，包括文件名和扩展名  
	return csFileFullName;  
}  

CString GetFileFullName(CString csFilePath)  
{  
	int nPos = csFilePath.ReverseFind('\\'); // 文件路径，以'\'斜杠分隔的路径  
	if (-1 == nPos)
	{
		return "";
	}
	CString csFileFullName;  
	csFileFullName = csFilePath.Right(csFilePath.GetLength() - nPos - 1); // 获取文件全名，包括文件名和扩展名  
	return csFileFullName;  
}  

CString GetFileName(CString csFileFullName)  
{  
	int nPos = csFileFullName.ReverseFind('.');  
	if (-1 == nPos)
	{
		return "";
	}
	CString  csFileName = csFileFullName.Left(nPos); // 获取文件名  
	return csFileName;  
}  

CString  GetFileExtName(CString csFileFullName)  
{  
	int nPos = csFileFullName.ReverseFind('.');  
	if (-1 == nPos)
	{
		return "";
	}
	CString  csFileExtName = csFileFullName.Right(csFileFullName.GetLength() - nPos - 1); // 获取扩展名  
	return csFileExtName;  
}

int CParserPostMsg::ReadFileInfo(std::string szFilePath, std::string& szBuf)
{

	FILE    *fp;
	int     len;

	fp=fopen(szFilePath.c_str(),"rb");
	if(!fp) return -1;

	fseek(fp,0,SEEK_END);
	long lLen = ftell(fp); //return NULL;
	if (lLen ==0)
	{
		fclose(fp);
		return 1;
	}

	char* pBuf = new char[lLen+1];
	memset(pBuf,0,lLen+1);

	fseek(fp,0,SEEK_SET);
	len=fread(pBuf,1,lLen,fp);
	fclose(fp);

	szBuf = pBuf;
	delete pBuf;
	return 0;
}

int CParserPostMsg::ReadByteFileInfo(std::string szFilePath)
{

	FILE    *fp;
	int     len;

	fp=fopen(szFilePath.c_str(),"rb");
	if(!fp) return -1;

	fseek(fp,0,SEEK_END);
	m_lLen = ftell(fp); //return NULL;
	if (m_lLen ==0)
	{
		fclose(fp);
		return 1;
	}

	m_btBuf = new BYTE[m_lLen+1];
	memset(m_btBuf,0,m_lLen+1);

	fseek(fp,0,SEEK_SET);
	len=fread(m_btBuf,1,m_lLen,fp);
	fclose(fp);
	return 0;
}

int CParserPostMsg::WriteFileInfo(std::string szResName,const std::string& strBuf, std::string& szNewPath)
{
	//得到新的文件名，在原来的文件名上加上年月日时分秒
	CString strPath = GetFilePath(szResName.c_str());
	CString strFullName = GetFileFullName(szResName.c_str());
	if (strPath.IsEmpty() || strFullName.IsEmpty())
	{
		return -1;
	}

	CString strName = GetFileName(strFullName);
	CString strExtName = GetFileExtName(strFullName);
	if (strName.IsEmpty() || strExtName.IsEmpty())
	{
		return -1;
	}


	FILE    *fp;
	int     len;


	fp=fopen(szNewPath.c_str() ,"w+");
	if(!fp) return -1;

	len = fwrite(strBuf.c_str(), 1,strBuf.length() ,fp);
	fclose(fp);
	return 0;
}

int CParserPostMsg::SendUserInfo(std::string szInfo)
{
	Json::Value jsVal;
	
	jsVal["UserInfo"] =szInfo;
	jsVal["resultCode"] ="0";
	SendResp(jsVal.toStyledString());
	return 0;
}

ReadCertInfo* CParserPostMsg::GetCertInfo(std::string szCertId,BOOL bFirst)
{
	//从Ukey中得到证书
	g_pCADlg->ClearData();
	g_pCADlg->CollectUSBInfo();
	g_pCADlg->ImportUKeyDlls();

	int nCount = g_pCADlg->m_vecCert.size();
	for (int i =0; i< nCount;i++)
	{
		CCSPCertificate cspCert;
		cspCert._DecodeX509Cert(g_pCADlg->m_vecCert[i].m_pCert, g_pCADlg->m_vecCert[i].m_ulCertLen);

		char lpValue[500] = {0};
		ULONG ulLen = 500;
		cspCert.get_SN(lpValue,&ulLen);
		if (0 ==  szCertId.compare(lpValue) ||bFirst)
		{

			return &(g_pCADlg->m_vecCert[i]);
		}
	}

	return NULL;
}



BOOL CParserPostMsg::SendResp(std::string szResp)
{
	if (m_pReq != NULL)
	{
		CHttpProtocol2 *pHttpProtocol = (CHttpProtocol2 *)m_pReq->pHttpProtocol;
		pHttpProtocol->SendLoginResp(m_pReq,szResp);


		//pHttpProtocol->Disconnect(m_pReq);
		delete m_pReq;
		m_pReq = NULL;
	//	pHttpProtocol->CountDown();	// client数量减1

		return TRUE;
	}

	return FALSE;

}

int CParserPostMsg::SOF_GetInstanceDW()
{
	// TODO: 在此添加控件通知处理程序代码
	if (!m_bSetIP)
	{
		LOG_INFO("Please set the server address first ");
		return (DealwithError("Please set the server address first "));
	}
	std::string szAppName = m_inRoot["appName"].asString();

	
	std::string szResp;
	int nReturn_ = -1;
	int nResp = 0;
	BOOL bResp = FALSE;


	if (0 == m_strUrl.Compare("GetInstance"))
	{
		nReturn_ = m_PSDM.PostHttpPage(SD_GETINSTANCE,m_inRoot,szResp);
		if (0 == nReturn_)
		{
			nReturn_ =m_PSDM.DealWithRecvMsg("webAPPName",szResp);
		}
	}
	else
	{
		ns1__SOF_USCOREGetInstance sofRequest;
		sofRequest.appName= &szAppName;
		LOG_INFO("SOF_USCOREGetInstance:AppName=%s",sofRequest.appName->c_str());
		nReturn_ = soapSender::SOF_USCOREGetInstance(sofRequest,szResp);
	}

	if (0 == nReturn_)
	{

		Json::Value jsVal;
		jsVal["resultCode"] = "0";
		SendResp(jsVal.toStyledString());
		return 0;
	}
	else
	{

		CString strInfo;
		strInfo.Format("SOF_USCOREGetInstance failed from server! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());

		DealwithError(strInfo.GetBuffer());
		LOG_ERROR(strInfo);
		return 1;

	}
}

int CParserPostMsg::SetServerDW()
{

	if (!m_inRoot["nPort"].isInt())
	{
		DealwithError("interface format is error");
		return 1;
	}

	m_bSetIP = TRUE;

	int nPort = m_inRoot["nPort"].asInt();
	std::string szIP = m_inRoot["sServer"].asString();
	soapSender::SetServerInfo(szIP,nPort);

	m_PSDM.m_nPort = nPort;
	m_PSDM.m_szHostName = szIP;

	Json::Value jsVal;
	jsVal["resultCode"] = "0";
	SendResp(jsVal.toStyledString());
	return 0;
}
