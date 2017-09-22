
//gosap Head Files


#include "WebService.h"
#include <Windows.h>
#include <time.h>
#include "HealthGateWayServiceServiceSoapBinding.nsmap"

#include "EnDecodeClass.h"

std::string soapSender::m_szServerIp="139.196.37.142";
int soapSender::m_nServerPort=8080;

static void TraceA(const char* fmt, ...)
{
	char moduleName[1024] = {0};
	static char buf[10240];
	int bytes;

	va_list argptr;
	va_start(argptr, fmt);

	bytes = sprintf(buf, "[%d] ",
		GetCurrentProcessId());

	vsprintf(buf + bytes, fmt, argptr);

	OutputDebugStringA(buf);
}

int soapSender::GetServerInfo(std::string szConfigFile)
{
	CHAR		szValueBuffer[100]			= {0};
	DWORD		dwValueBufferSize			= sizeof(szValueBuffer)/sizeof(TCHAR);
	GetPrivateProfileStringA("Common","ServerIP","",szValueBuffer,dwValueBufferSize,szConfigFile.c_str());
	m_szServerIp = szValueBuffer;
	m_nServerPort = GetPrivateProfileIntA("Common","ServerPort", m_nServerPort,szConfigFile.c_str());
	return 0;
}

void soapSender::SetServerInfo(std::string szIP, int nPort)
{
	m_szServerIp = szIP;
	m_nServerPort = nPort;
}



/************************************************************************/
/*                      soapSender                                      */
/************************************************************************/

std::string soapSender::agentMessage(std::string szRequest, std::string szServerIp, int nServerPort, int nTimeOut)
{
	std::string	szResp = "";
	struct soap userinfoSoap;
	WS1__SOF_USCOREGenRandom helloWorld;
	WS1__SOF_USCOREGenRandomResponse helloWorldResponse;
//	const char *pcAddr="http://139.196.37.142:8080/camanager/webservice/?wsdl";
	const char *pcAddr ="http://139.196.37.142:8080/camanager/webservice/sOF_GenRandom";
	//helloWorld.tokenId = new std::string("9877654433");
	helloWorld.len= 6;
	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;
	int iRet = soap_call___WS1__SOF_USCOREGenRandom(&userinfoSoap,pcAddr,NULL,&helloWorld,&helloWorldResponse);
	//iRet=soap_call___WS1__HelloWorld(&userinfoSoap,pcAddr,NULL,&helloWorld,&helloWorldResponse);
	if(iRet!=0)
	{
		printf("读取数据失败");
	}
	else
	{
		printf("读取数据成功：%s",helloWorldResponse);
	}
	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return szResp;
}


//得到随机数
int soapSender::SOF_USCOREGenRandom(WS1__SOF_USCOREGenRandom& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_GenRandom", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREGenRandomResponse sofResponse;

	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREGenRandom(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);
	if (iRet==0)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}

	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

//获得一个对象实例，初始化对象
int soapSender::SOF_USCOREGetInstance(WS1__SOF_USCOREGetInstance& sofRequest,std::string& szResp, int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_GetInstance", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREGetInstanceResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREGetInstance(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0)
	{
		if (NULL != sofResponse.return_)
		{
			szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_->webAppName));
		}
		else
		{
			return 1;
		}
		
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}
int soapSender::SOF_VerifySignedData(WS1__SOF_USCOREVerifySignedData& sofRequest,BOOL& bSuccess,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_VerifySignedData", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREVerifySignedDataResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREVerifySignedData(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0)
	{
		bSuccess = sofResponse.return_;
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_QueryCertTrustList(WS1__SOF_USCOREQueryCertTrustList& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_QueryCertTrustList", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREQueryCertTrustListResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREQueryCertTrustList(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}
//SOF_VerifySignedDataByP7
int soapSender::SOF_VerifySignedDataByP7(WS1__SOF_USCOREVerifySignedDataByP7& sofRequest, BOOL& bSuccess,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_VerifySignedDataByP7", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREVerifySignedDataByP7Response sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREVerifySignedDataByP7(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0)
	{
		bSuccess = sofResponse.return_;
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

//SOF_SetCertTrustList
int soapSender::SOF_SetCertTrustList(WS1__SOF_USCORESetCertTrustList& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_SetCertTrustList", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCORESetCertTrustListResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCORESetCertTrustList(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

//GetP7SignDataInfo
int soapSender::SOF_GetP7SignDataInfo(WS1__SOF_USCOREGetP7SignDataInfo& sofRequest, std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_GetP7SignDataInfo", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREGetP7SignDataInfoResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREGetP7SignDataInfo(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 &&(sofResponse.return_ != NULL))
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}
//SOF_VerifyTimeStamp
int soapSender::SOF_VerifyTimeStamp(WS1__SOF_USCOREVerifyTimeStamp& sofRequest, BOOL& bSuccess,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_VerifyTimeStamp", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREVerifyTimeStampResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREVerifyTimeStamp(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0)
	{
		bSuccess = sofResponse.return_;
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

//SOF_PubKeyEncrypt
int soapSender::SOF_PubKeyEncrypt(WS1__SOF_USCOREPubKeyEncrypt& sofRequest, std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_PubKeyEncrypt", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREPubKeyEncryptResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREPubKeyEncrypt(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_VerifySignedFile(WS1__SOF_USCOREVerifySignedFile& sofRequest,BOOL& bSuccess,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_VerifySignedFile", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREVerifySignedFileResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREVerifySignedFile(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0)
	{
		bSuccess = sofResponse.return_;
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_GetServerCertificate(WS1__SOF_USCOREGetServerCertificate& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_GetServerCertificate", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREGetServerCertificateResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREGetServerCertificate(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_GetCertInfoByOid(WS1__SOF_USCOREGetCertInfoByOid& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_GetCertInfoByOid", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREGetCertInfoByOidResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREGetCertInfoByOid(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_DelCertTrustList(WS1__SOF_USCOREDelCertTrustList& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_DelCertTrustList", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREDelCertTrustListResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREDelCertTrustList(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_GetXMLSignatureInfo(WS1__SOF_USCOREGetXMLSignatureInfo& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_GetXMLSignatureInfo", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREGetXMLSignatureInfoResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREGetXMLSignatureInfo(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_VerifySignedDataXML(WS1__SOF_USCOREVerifySignedDataXML& sofRequest,BOOL& bSuccess,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_VerifySignedDataXML", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREVerifySignedDataXMLResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREVerifySignedDataXML(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0)
	{
		bSuccess = sofResponse.return_;
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_SignData(WS1__SOF_USCORESignData& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_SignData", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCORESignDataResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCORESignData(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_SignFile(WS1__SOF_USCORESignFile& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_SignFile", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCORESignFileResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCORESignFile(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_PriKeyDecrypt(WS1__SOF_USCOREPriKeyDecrypt& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_PriKeyDecrypt", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREPriKeyDecryptResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREPriKeyDecrypt(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_SetWebAppName(WS1__SOF_USCORESetWebAppName& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_SetWebAppName", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCORESetWebAppNameResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCORESetWebAppName(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_GetSignMethod(WS1__SOF_USCOREGetSignMethod& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_GetSignMethod", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREGetSignMethodResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREGetSignMethod(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_SetEncryptMethod(WS1__SOF_USCORESetEncryptMethod& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_SetEncryptMethod", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCORESetEncryptMethodResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCORESetEncryptMethod(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_CreateTimeStampRequest(WS1__SOF_USCORECreateTimeStampRequest& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_CreateTimeStampRequest", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCORECreateTimeStampRequestResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCORECreateTimeStampRequest(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_GetEncryptMethod(WS1__SOF_USCOREGetEncryptMethod& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_GetEncryptMethod", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREGetEncryptMethodResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREGetEncryptMethod(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_CreateTimeStampResponse(WS1__SOF_USCORECreateTimeStampResponse& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_CreateTimeStampResponse", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCORECreateTimeStampResponseResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCORECreateTimeStampResponse(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_ValidateCert(WS1__SOF_USCOREValidateCert& sofRequest,int& nResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_ValidateCert", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREValidateCertResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREValidateCert(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0)
	{
		nResp = sofResponse.return_;
	}
	else
	{
		nResp = sofResponse.return_;
	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_DecryptFile(WS1__SOF_USCOREDecryptFile& sofRequest,BOOL& bSuccess,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_DecryptFile", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREDecryptFileResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREDecryptFile(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0)
	{
		bSuccess = sofResponse.return_;
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_SetSignMethod(WS1__SOF_USCORESetSignMethod& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_SetSignMethod", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCORESetSignMethodResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCORESetSignMethod(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_GetTimeStampInfo(WS1__SOF_USCOREGetTimeStampInfo& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_GetTimeStampInfo", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREGetTimeStampInfoResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREGetTimeStampInfo(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_SignDataByP7(WS1__SOF_USCORESignDataByP7& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_SignDataByP7", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCORESignDataByP7Response sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCORESignDataByP7(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_EncryptFile(WS1__SOF_USCOREEncryptFile& sofRequest,BOOL& bSuccess,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_EncryptFile", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREEncryptFileResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREEncryptFile(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0)
	{
		bSuccess = sofResponse.return_;
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_SignDataXML(WS1__SOF_USCORESignDataXML& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_SignDataXML", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCORESignDataXMLResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCORESignDataXML(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_DecryptData(WS1__SOF_USCOREDecryptData& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_DecryptData", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREDecryptDataResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREDecryptData(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_QueryCertTrustListAltNames(WS1__SOF_USCOREQueryCertTrustListAltNames& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_QueryCertTrustListAltNames", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREQueryCertTrustListAltNamesResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREQueryCertTrustListAltNames(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_GetCertInfo(WS1__SOF_USCOREGetCertInfo& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_GetCertInfo", m_szServerIp.c_str(), m_nServerPort);

	std::locale loc1 = std::locale::global(std::locale(".936"));
	struct soap userinfoSoap(SOAP_C_MBSTRING);
	WS1__SOF_USCOREGetCertInfoResponse sofResponse;
	//setlocal(LC_ALL,"chs");
	


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREGetCertInfo(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}

int soapSender::SOF_EncryptData(WS1__SOF_USCOREEncryptData& sofRequest,std::string& szResp,int nTimeOut)
{
	char		pcAddr[200] = {0};
	sprintf(pcAddr, "http://%s:%d/camanager/webservice/sOF_EncryptData", m_szServerIp.c_str(), m_nServerPort);

	struct soap userinfoSoap;
	WS1__SOF_USCOREEncryptDataResponse sofResponse;


	soap_init(&userinfoSoap);
	userinfoSoap.connect_timeout = 1;
	userinfoSoap.send_timeout = userinfoSoap.recv_timeout = nTimeOut;

	int iRet = soap_call___WS1__SOF_USCOREEncryptData(&userinfoSoap,pcAddr,NULL,&sofRequest,&sofResponse);

	if (iRet==0 && sofResponse.return_ !=NULL)
	{
		szResp = CEnDecodeClass::StringW2A(*(sofResponse.return_));
	}
	else
	{

	}


	soap_destroy(&userinfoSoap);   
	soap_end(&userinfoSoap);   
	soap_done(&userinfoSoap);   
	return iRet;
}
