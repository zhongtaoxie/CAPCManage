#include "StdAfx.h"
#include "ParserSDMsg.h"

#include "EnDecodeClass.h"

extern CString g_strExePath;

CParserSDMsg::CParserSDMsg(void)
{
	m_nPort = 8000;
}

CParserSDMsg::~CParserSDMsg(void)
{
}

//void CParserSDMsg::SetMsgHead(std::string& szHead)
//{
//
//	char msg[2048] = " ";
//	char curTime[50] = " ";
//	GetCurentTime((char*)curTime);
//
//
//	sprintf((char*)msg, "HTTP/1.1 200 OK\r\n%s\r\n%s\r\nContent-Type: %s\r\nContent-Length: %d\r\n%s",
//		"Server: Apache-Coyote/1.1",				// Date
//		"Access-Control-Allow-Origin: *",       // Server
//		"application/json;charset=UTF-8",		// Content-Type
//		length,					// Content-length
//		curTime);
//
//	// 返回响应
//
//	int sdf = strlen(msg);
//
//	send(pReq->Socket, msg, strlen(msg), 0);	
//
//	LOG_INFO(szResp.c_str());
//}

int CParserSDMsg::RunGmssl()
{
	CString strGmsslExe = g_strExePath + "\\gmssl\\gmssl.exe";
	CString strCert =g_strExePath + "\\gmssl\\key\\myclient-cert.pem";
	CString strKey = g_strExePath + "\\gmssl\\key\\myclient-key.pem";


	CString strIP =m_szHostName.c_str();
	int nPort = m_nPort;
	CString strInfo;
	strInfo.Format("%s s_client -connect %s:%d -cert %s -key %s  -msg -state -debug",strGmsslExe,strIP,nPort,strCert,strKey);
//	CString strData = "D:\\key\\08\\gmssl.exe s_client -connect 127.0.0.1:4433 -cert s_server -cert D:\\key\\myserver-cert.pem -key D:\\key\\myserver-key.pem -msg -state -debug";
	WinExec(strInfo, SW_HIDE);

	return 0;
}


int CParserSDMsg::PostHttpPage(std::string pathName, Json::Value& jsData,std::string& szOut)
{
	RunGmssl();
	std::string postData;
	if(!PreDealWithMsg(pathName,jsData,postData))
	{
		return -1;
	}

	CInternetSession session("your app agent name");
	int nRet =0;

	try
	{
		DWORD dwRet = 0;

		pathName ="camanager/"+pathName;

		CHttpConnection* pServer = session.GetHttpConnection(m_szHostName.c_str(),m_nPort);
		CHttpFile* pFile = pServer->OpenRequest(CHttpConnection::HTTP_VERB_POST,pathName.c_str());
		CString strHeaders = "Content-Type: application/json;charset=UTF-8"; //请求头

		//开始发送请求

		CEnDecodeClass::Gbk2Utf(postData);

		pFile->SendRequest(strHeaders,(LPVOID)postData.c_str(),postData.size());
		pFile->QueryInfoStatusCode(dwRet);

		if (dwRet == HTTP_STATUS_OK)
		{
			CString result, newline;

			while(pFile->ReadString(newline))
			{//循环读取每行内容
				result += newline;//+"\r\n";
			}

			szOut = result;
			CEnDecodeClass::Utf2Gbk(szOut);
			LOG_INFO(szOut.c_str());
		}
		else
		{
			LOG_INFO("server return error,error code=%d",dwRet);
		}

		delete pFile;
		delete pServer;
	}
	catch (CInternetException* pEx)
	{
		//catch errors from WinInet
		CHAR pszError[200];
		pEx->GetErrorMessage(pszError, 200);
		LOG_INFO(pszError);

		nRet = -1;
	}
	session.Close();

	return nRet;
}

BOOL CParserSDMsg::PreDealWithMsg(const std::string& szType,Json::Value& jsData, std::string& szOutData)
{
	Json::Value jsOutData;
	if (SD_SETSIGNMETHOD == szType)
	{
		jsOutData["signMethod"]=jsData["SignMethod"];
	}
	else if (SD_SETENCRYPTMETHOD == szType)
	{
		jsOutData["encryptMethod"]=jsData["EncryptMethod"];
	}
	else if (SD_GETCERTINFO == szType)
	{
		jsOutData["base64EncodeCert"] = jsData["Cert"];
		char buf[10]={0};
		_itoa_s(jsData["Type"].asInt(), buf, 10,10);
		jsOutData["type"] = buf;
	}
	else if (SD_GETCERTINFOBYOID == szType)
	{
		jsOutData["base64EncodeCert"] = jsData["Cert"];
		jsOutData["oid"] = jsData["Oid"].asString();
	}
	else if (SD_VALIDDATECERT == szType)
	{
		jsOutData["base64EncodeCert"] = jsData["Cert"];
	}
	else if (SD_VERIFYSIGNEDDATA == szType)
	{
		jsOutData["base64EncodeCert"] = jsData["Cert"];
		jsOutData["inData"] = jsData["InData"];
		jsOutData["signValue"] = jsData["SignValue"];
	}
	/*else if (SD_VERIFYSIGNEDFILE == szType)
	{
		jsOutData["base64EncodeCert"] = jsData["Cert"];
		jsOutData["inData"] = jsData["InData"];
		jsOutData["signValue"] = jsData["SignValue"];
	}*/
	else if (SD_VERIFYSIGNEDDATABYP7 == szType)
	{
		jsOutData["pkcs7SignData"] = jsData["P7Data"];
	}
	else if (SD_GETP7SIGNDATAINFO == szType)
	{
		jsOutData["pkcs7SignData"] = jsData["P7Data"];
		jsOutData["type"] = jsData["type"];
	}
	else if (SD_VERIFYSIGNEDDATAXML == szType)
	{
		jsOutData["inData"] = jsData["InData"];
	}
	else if (SD_GETXMLSIGNTUREINFO == szType)
	{
		jsOutData["XMLSignedData"] = jsData["XMLSignedData"];
		jsOutData["type"] = jsData["type"];
	}
	else if (SD_GENRANDOM == szType)
	{
		jsOutData["len"] = jsData["len"];
	}
	else if (SD_GETINSTANCE == szType)
	{
		jsOutData["appName"] = jsData["appName"];
	}


	szOutData = jsOutData.toStyledString();


	return TRUE;
}

int CParserSDMsg::DealWithRecvMsg(const std::string& szType, std::string& szData)
{
	Json::Reader jReader;
	Json::Value jsVal;
	int nRet = -1;

	if (!jReader.parse(szData, jsVal) || jsVal.isNull())  
	{
		return nRet;
	}
	else if (!jsVal.isObject())
	{
		return nRet;
	}

	if (!jsVal[szType].isString())
	{
		return nRet;
	}

	szData = jsVal[szType].asString();

	nRet = 0;

	return nRet;
}
