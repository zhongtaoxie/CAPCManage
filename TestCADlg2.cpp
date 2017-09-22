// TestCADlg2.cpp : 实现文件
//

#include "stdafx.h"
#include "CAPCManage.h"
#include "TestCADlg2.h"
#include "../soapSender/WebService.h"
#include "../Include/Guomi/SKFAPI.h"
#include "ReadUKey.h"
#include "PinDlg.h"
#include "EnDecodeClass.h"

extern std::string g_szbase64Cert;
extern CReadUKey* g_readUKey;

std::string g_szTimeStampRes;
std::string g_szTimeStampRep;
std::string g_szXmlCert;
std::string g_szP7Sign;
std::string g_szEncrytFile;
// CTestCADlg2 对话框

IMPLEMENT_DYNAMIC(CTestCADlg2, CDialog)

CTestCADlg2::CTestCADlg2(CWnd* pParent /*=NULL*/)
	: CDialog(CTestCADlg2::IDD, pParent)
{

}

CTestCADlg2::~CTestCADlg2()
{
}

void CTestCADlg2::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CTestCADlg2, CDialog)
	ON_BN_CLICKED(IDC_BTN_GENRANDOM, &CTestCADlg2::OnBnClickedBtnGenrandom)
	ON_BN_CLICKED(IDC_BTN_GETINSTANCE, &CTestCADlg2::OnBnClickedBtnGetinstance)
	ON_BN_CLICKED(IDC_BTN_VERIFY_SIGNED_DATA, &CTestCADlg2::OnBnClickedBtnVerifySignedData)
	ON_BN_CLICKED(IDC_BTN_QUERY_CERTTRUSTLIST, &CTestCADlg2::OnBnClickedBtnQueryCerttrustlist)
	ON_BN_CLICKED(IDC_BTN_VERIFY_SIGNEDDATABYP7, &CTestCADlg2::OnBnClickedBtnVerifySigneddatabyp7)
	ON_BN_CLICKED(IDC_BTN_SET_CERTTRUSTLIST, &CTestCADlg2::OnBnClickedBtnSetCerttrustlist)
	ON_BN_CLICKED(IDC_BTN_GET_P7SIGNDATAINFO, &CTestCADlg2::OnBnClickedBtnGetP7signdatainfo)
	ON_BN_CLICKED(IDC_BTN_VERIFY_TIMESTAMP, &CTestCADlg2::OnBnClickedBtnVerifyTimestamp)
	ON_BN_CLICKED(IDC_BTN_PUBKEY_ENCRYPT, &CTestCADlg2::OnBnClickedBtnPubkeyEncrypt)
	ON_BN_CLICKED(IDC_BTN_VERIFYSIGNEDFILE, &CTestCADlg2::OnBnClickedBtnVerifysignedfile)
	ON_BN_CLICKED(IDC_BTN_GET_SERVERCERTIFICATE, &CTestCADlg2::OnBnClickedBtnGetServercertificate)
	ON_BN_CLICKED(IDC_BTN_GET_CERTINFOBYOID, &CTestCADlg2::OnBnClickedBtnGetCertinfobyoid)
	ON_BN_CLICKED(IDC_BTN_DEL_CERTTRUSTLIST, &CTestCADlg2::OnBnClickedBtnDelCerttrustlist)
	ON_BN_CLICKED(IDC_BTN_GET_XMLSIGNATUREINFO, &CTestCADlg2::OnBnClickedBtnGetXmlsignatureinfo)
	ON_BN_CLICKED(IDC_BTN_VERIFY_SIGNEDDATAXML, &CTestCADlg2::OnBnClickedBtnVerifySigneddataxml)
	ON_BN_CLICKED(IDC_BTN_SIGN_DATA, &CTestCADlg2::OnBnClickedBtnSignData)
	ON_BN_CLICKED(IDC_BTN_SIGN_FILE, &CTestCADlg2::OnBnClickedBtnSignFile)
	ON_BN_CLICKED(IDC_BTN_PRIKEY_DECRYPT, &CTestCADlg2::OnBnClickedBtnPrikeyDecrypt)
	ON_BN_CLICKED(IDC_BTN_SET_WEBAPPNAME, &CTestCADlg2::OnBnClickedBtnSetWebappname)
	ON_BN_CLICKED(IDC_BTN_GET_SIGNMETHOD, &CTestCADlg2::OnBnClickedBtnGetSignmethod)
	ON_BN_CLICKED(IDC_BTN_SET_ENCRYPTMETHOD, &CTestCADlg2::OnBnClickedBtnSetEncryptmethod)
	ON_BN_CLICKED(IDC_BTN_CREATE_TIMESTAMPREQUEST, &CTestCADlg2::OnBnClickedBtnCreateTimestamprequest)
	ON_BN_CLICKED(IDC_BTN_GET_ENCRYPTMETHOD, &CTestCADlg2::OnBnClickedBtnGetEncryptmethod)
	ON_BN_CLICKED(IDC_BTN_CREATE_TIMESTAMPRESPONSE, &CTestCADlg2::OnBnClickedBtnCreateTimestampresponse)
	ON_BN_CLICKED(IDC_BTN_VALIDATE_CERT, &CTestCADlg2::OnBnClickedBtnValidateCert)
	ON_BN_CLICKED(IDC_BTN_DECRYPT_FILE, &CTestCADlg2::OnBnClickedBtnDecryptFile)
	ON_BN_CLICKED(IDC_BTN_SET_SIGNMETHOD, &CTestCADlg2::OnBnClickedBtnSetSignmethod)
	ON_BN_CLICKED(IDC_BTN_GET_TIMESTAMPINFO, &CTestCADlg2::OnBnClickedBtnGetTimestampinfo)
	ON_BN_CLICKED(IDC_BTN_SIGN_DATABYP7, &CTestCADlg2::OnBnClickedBtnSignDatabyp7)
	ON_BN_CLICKED(IDC_BTN_ENCRYPT_FILE, &CTestCADlg2::OnBnClickedBtnEncryptFile)
	ON_BN_CLICKED(IDC_BTN_SIGN_DATAXML, &CTestCADlg2::OnBnClickedBtnSignDataxml)
	ON_BN_CLICKED(IDC_BTN_DECRYPT_DATA, &CTestCADlg2::OnBnClickedBtnDecryptData)
	ON_BN_CLICKED(IDC_BTN_QUERY_CERTTRUSTLISTALTNAMES, &CTestCADlg2::OnBnClickedBtnQueryCerttrustlistaltnames)
	ON_BN_CLICKED(IDC_BTN_GET_CERTINFO, &CTestCADlg2::OnBnClickedBtnGetCertinfo)
	ON_BN_CLICKED(IDC_BTN_ENCRYPT_DATA, &CTestCADlg2::OnBnClickedBtnEncryptData)
END_MESSAGE_MAP()


// CTestCADlg2 消息处理程序
//是base64，需要解码---xzt
void CTestCADlg2::OnBnClickedBtnGenrandom()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREGenRandom sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.len= 10;

	LOG_INFO("SOF_USCOREGenRandom:tokenId=%s,len=%d", szToken.c_str(),sofRequest.len);

	int nReturn_ = soapSender::SOF_USCOREGenRandom(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_USCOREGenRandom succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnGetinstance()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREGetInstance sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.appName= new std::wstring(L"xzt");

	LOG_INFO("SOF_USCOREGetInstance:tokenId=%s,appName=%s", szToken.c_str(),sofRequest.appName->c_str());

	int nReturn_ = soapSender::SOF_USCOREGetInstance(sofRequest,szResp);
	if (0 == nReturn_)
	{
		AfxMessageBox(szResp.c_str());
	}
}

void CTestCADlg2::OnBnClickedBtnVerifySignedData()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szbase64Cert.empty())
	{
		AfxMessageBox("证书为空，请先用主窗口的导出按钮导出证书");
		return;
	}

	CPinDlg dlg;
	if (IDOK != dlg.DoModal())
	{
		return;
	}

	std::string szRandom ="qwertyuiop1234567890asdfghjkl132";
	BYTE* pbSignature = NULL;
	ULONG ulSignLen = 0;

	ULONG rv = 0;

	if (g_readUKey->m_ulType == CERT_KEY_ALG_RSA)
	{
		rv = g_readUKey->RSASignDataEx(g_readUKey->m_hAContainer,szRandom, pbSignature, &ulSignLen);
	}
	else
	{
		rv = g_readUKey->ECCSignDataEx(g_readUKey->m_hAContainer,szRandom, pbSignature, &ulSignLen);
	}

	if (rv)
	{
		if (pbSignature!= NULL)
		{
			free(pbSignature);
			pbSignature = NULL;
		}
		//打印出随机数和证书内容
		LOG_INFO("对随机数进行签名失败！ 随机数=%s,证书内容=%s", szRandom.c_str(),g_szbase64Cert.c_str());
		AfxMessageBox("对随机数进行签名失败！");
		return;
	}

	WS1__SOF_USCOREVerifySignedData sofRequest;
	BOOL bResp = FALSE;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	std::string szSign((char*)pbSignature);
	if (pbSignature!= NULL)
	{
		free(pbSignature);
		pbSignature = NULL;
	}
	sofRequest.signValue = &CEnDecodeClass::StringA2W(szSign);
	sofRequest.inData = &CEnDecodeClass::StringA2W(szRandom);

	sofRequest.base64EncodeCert =&CEnDecodeClass::StringA2W(g_szbase64Cert);

	LOG_INFO("sofRequest.inData=%s,sofRequest.signValue=%s,sofRequest.base64EncodeCert=\r\n%s", szRandom.c_str(),szSign.c_str(),g_szbase64Cert.c_str());


	int nReturn_ = soapSender::SOF_VerifySignedData(sofRequest, bResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_VerifySignedData succeed! bResp=%d",bResp);
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_VerifySignedData failed! nReturn_=%d,bResp=%d",nReturn_, bResp);
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnQueryCerttrustlist()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREQueryCertTrustList sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	std::string szname("xzt");
	//sofRequest.tokenId = &szToken;
	sofRequest.fCtlAltname = &CEnDecodeClass::StringA2W(szname);

	LOG_INFO("SOF_QueryCertTrustList:tokenId=%s,sofRequest.fCtlAltname=%s", szToken.c_str(),
		                                                                     sofRequest.fCtlAltname->c_str());

	int nReturn_ = soapSender::SOF_QueryCertTrustList(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_QueryCertTrustList succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_QueryCertTrustList failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnVerifySigneddatabyp7()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szP7Sign.empty())
	{
		AfxMessageBox("请先单击SOF_SignDataByP7按钮，获得P7签名");
		return;
	}
	WS1__SOF_USCOREVerifySignedDataByP7 sofRequest;
	BOOL bResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.pkcs7SignData =&CEnDecodeClass::StringA2W(g_szP7Sign);
	LOG_INFO("SOF_VerifySignedDataByP7:sofRequest.pkcs7SignData=%s",sofRequest.pkcs7SignData->c_str());

	int nReturn_ = soapSender::SOF_VerifySignedDataByP7(sofRequest, bResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_VerifySignedDataByP7 succeed! bResp=%d",bResp);
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_VerifySignedDataByP7 failed! nReturn_=%d,bResp=%d",nReturn_, bResp);
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnSetCerttrustlist()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCORESetCertTrustList sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;

	int nReturn_ = soapSender::SOF_SetCertTrustList(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_SetCertTrustList succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_SetCertTrustList failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnGetP7signdatainfo()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szP7Sign.empty())
	{
		AfxMessageBox("请先单击SOF_SignDataByP7按钮，获得P7签名");
		return;
	}
	WS1__SOF_USCOREGetP7SignDataInfo sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.pkcs7SignData =&CEnDecodeClass::StringA2W(g_szP7Sign);
	sofRequest.type =1;
	LOG_INFO("SOF_GetP7SignDataInfo:sofRequest.pkcs7SignData=%s,sofRequest.type=%d",sofRequest.pkcs7SignData->c_str(),
		                                                            sofRequest.type);

	int nReturn_ = soapSender::SOF_GetP7SignDataInfo(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_GetP7SignDataInfo succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_GetP7SignDataInfo failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnVerifyTimestamp()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szTimeStampRep.empty())
	{
		AfxMessageBox("时间戳为空，请先调用分别调用SOF_CreateTimeStampRequest，SOF_CreateTimeStampResponse函数");
		return;
	}
	WS1__SOF_USCOREVerifyTimeStamp sofRequest;
	BOOL bResp;

	std::string szToken("9877654433");
	std::string szData("qwertasdf");
	//sofRequest.tokenId = &szToken;
	sofRequest.content =&CEnDecodeClass::StringA2W(szData);
	sofRequest.tsResponseData = &CEnDecodeClass::StringA2W(g_szTimeStampRep);

	LOG_INFO("SOF_VerifyTimeStamp:sofRequest.content=%s,sofRequest.tsResponseData",sofRequest.content->c_str(),
		                                                                        sofRequest.tsResponseData->c_str());

	int nReturn_ = soapSender::SOF_VerifyTimeStamp(sofRequest, bResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_VerifyTimeStamp succeed! bResp=%d",bResp);
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_VerifyTimeStamp failed! nReturn_=%d,bResp=%d",nReturn_, bResp);
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnPubkeyEncrypt()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szbase64Cert.empty())
	{
		AfxMessageBox("证书为空，请先用主窗口的导出按钮导出证书");
		return;
	}
	WS1__SOF_USCOREPubKeyEncrypt sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.base64EncodeCert = &CEnDecodeClass::StringA2W(g_szbase64Cert);
	std::string szdata("asfweras");
	sofRequest.inData =&CEnDecodeClass::StringA2W(szdata);

	LOG_INFO("SOF_PubKeyEncrypt:sofRequest.base64EncodeCert=\r\n%s\r\nsofRequest.inData=%s",
		                                                               sofRequest.base64EncodeCert->c_str(),
																	   sofRequest.inData->c_str());

	int nReturn_ = soapSender::SOF_PubKeyEncrypt(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_PubKeyEncrypt succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
		g_szEncrytFile =szResp;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_PubKeyEncrypt failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnVerifysignedfile()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREVerifySignedFile sofRequest;
	BOOL bResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;

	int nReturn_ = soapSender::SOF_VerifySignedFile(sofRequest, bResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_VerifySignedFile succeed! bResp=%s",bResp);
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_VerifySignedFile failed! nReturn_=%d,bResp=%s",nReturn_, bResp);
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnGetServercertificate()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREGetServerCertificate sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.certUsage = 2;

	LOG_INFO("SOF_GetServerCertificate:sofRequest.certUsage=%d",
														  sofRequest.certUsage);

	int nReturn_ = soapSender::SOF_GetServerCertificate(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_GetServerCertificate succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_GetServerCertificate failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnGetCertinfobyoid()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szbase64Cert.empty())
	{
		AfxMessageBox("证书为空，请先用主窗口的导出按钮导出证书");
		return;
	}

	WS1__SOF_USCOREGetCertInfoByOid sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.base64EncodeCert = &CEnDecodeClass::StringA2W(g_szbase64Cert);
	std::string szdata("1.2.156.xxx");
	sofRequest.oid = &CEnDecodeClass::StringA2W(szdata);
	LOG_INFO("SOF_GetCertInfoByOid:sofRequest.base64EncodeCert=%s,\r\nsofRequest.oid=%s",
		sofRequest.base64EncodeCert->c_str(),
		sofRequest.oid->c_str());



	int nReturn_ = soapSender::SOF_GetCertInfoByOid(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_GetCertInfoByOid succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_GetCertInfoByOid failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnDelCerttrustlist()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREDelCertTrustList sofRequest;
	std::string szResp;

	//std::string szToken("xzt");
	std::string szname("xzt");
	sofRequest.fCtlAltname = &CEnDecodeClass::StringA2W(szname);//------没有token   xzt

	LOG_INFO("SOF_DelCertTrustList:sofRequest.fCtlAltname=%s",sofRequest.fCtlAltname->c_str());

	int nReturn_ = soapSender::SOF_DelCertTrustList(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_DelCertTrustList succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_DelCertTrustList failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnGetXmlsignatureinfo()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szXmlCert.empty())
	{
		AfxMessageBox("请先调用SOF_SignDataXML函数");
		return;
	}
	WS1__SOF_USCOREGetXMLSignatureInfo sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.XMLSignedData =&CEnDecodeClass::StringA2W(g_szXmlCert);
	sofRequest.type = 1;

	LOG_INFO("SOF_GetXMLSignatureInfo:sofRequest.XMLSignedData=%s,sofRequest.type=%d",sofRequest.XMLSignedData->c_str(),
		                                                                              sofRequest.type);

	int nReturn_ = soapSender::SOF_GetXMLSignatureInfo(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_GetXMLSignatureInfo succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_GetXMLSignatureInfo failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnVerifySigneddataxml()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szXmlCert.empty())
	{
		AfxMessageBox("请先调用SOF_SignDataXML函数");
		return;
	}
	WS1__SOF_USCOREVerifySignedDataXML sofRequest;
	BOOL bResp = FALSE;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.inData =&CEnDecodeClass::StringA2W(g_szXmlCert);

	LOG_INFO("SOF_VerifySignedDataXML:sofRequest.inData=%s", sofRequest.inData->c_str());

	int nReturn_ = soapSender::SOF_VerifySignedDataXML(sofRequest, bResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_VerifySignedDataXML succeed! bResp=%d",bResp);
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_VerifySignedDataXML failed! nReturn_=%d,bResp=%d",nReturn_, bResp);
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnSignData()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCORESignData sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	std::string szdata("nanjingca");
	sofRequest.inData = &CEnDecodeClass::StringA2W(szdata);
	LOG_INFO("SOF_SignData:sofRequest.inData=%s",sofRequest.inData->c_str());

	int nReturn_ = soapSender::SOF_SignData(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_SignData succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_SignData failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnSignFile()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCORESignFile sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;

	int nReturn_ = soapSender::SOF_SignFile(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_SignFile succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_SignFile failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnPrikeyDecrypt()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szEncrytFile.empty())
	{
		AfxMessageBox("请先单击SOF_PubKeyEncrypt产生密文");
	}
	WS1__SOF_USCOREPriKeyDecrypt sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.inData = &CEnDecodeClass::StringA2W(g_szEncrytFile);
	LOG_INFO("SOF_PriKeyDecrypt:sofRequest.inData=%s",sofRequest.inData->c_str());

	int nReturn_ = soapSender::SOF_PriKeyDecrypt(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_PriKeyDecrypt succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_PriKeyDecrypt failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnSetWebappname()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCORESetWebAppName sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;

	int nReturn_ = soapSender::SOF_SetWebAppName(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_SetWebAppName succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_SetWebAppName failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnGetSignmethod()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREGetSignMethod sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;


	int nReturn_ = soapSender::SOF_GetSignMethod(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_GetSignMethod succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_GetSignMethod failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnSetEncryptmethod()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCORESetEncryptMethod sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.encryptMethod = SGD_SM2_1;
	LOG_INFO("SOF_SetEncryptMethod:sofRequest.encryptMethod=%d",sofRequest.encryptMethod);

	int nReturn_ = soapSender::SOF_SetEncryptMethod(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_SetEncryptMethod succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_SetEncryptMethod failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnCreateTimestamprequest()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCORECreateTimeStampRequest sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	std::string szData("qwertasdf");
	//sofRequest.tokenId = &szToken;
	sofRequest.inData =&CEnDecodeClass::StringA2W(szData);
	LOG_INFO("SOF_CreateTimeStampRequest:sofRequest.inData=%s",sofRequest.inData->c_str());

	int nReturn_ = soapSender::SOF_CreateTimeStampRequest(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_CreateTimeStampRequest succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
		g_szTimeStampRes = szResp;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_CreateTimeStampRequest failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnGetEncryptmethod()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREGetEncryptMethod sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;

//	LOG_INFO("SOF_GetEncryptMethod:sofRequest.tokenId=%s",sofRequest.tokenId->c_str());

	int nReturn_ = soapSender::SOF_GetEncryptMethod(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_GetEncryptMethod succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_GetEncryptMethod failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnCreateTimestampresponse()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szTimeStampRes.empty())
	{
		AfxMessageBox("请先调用SOF_CreateTimeStampRequest创建时间戳请求");
		return;
	}
	WS1__SOF_USCORECreateTimeStampResponse sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.inData =&CEnDecodeClass::StringA2W(g_szTimeStampRes);
	LOG_INFO("SOF_CreateTimeStampResponse:sofRequest.inData=%s",sofRequest.inData);

	int nReturn_ = soapSender::SOF_CreateTimeStampResponse(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_CreateTimeStampResponse succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
		g_szTimeStampRep = szResp;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_CreateTimeStampResponse failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnValidateCert()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szbase64Cert.empty())
	{
		AfxMessageBox("证书为空，请先用主窗口的导出按钮导出证书");
		return;
	}
	WS1__SOF_USCOREValidateCert sofRequest;
	int nResp = 0;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.base64EncodeCert = &CEnDecodeClass::StringA2W(g_szbase64Cert);

	LOG_INFO("SOF_ValidateCert:sofRequest.base64EncodeCert=%s",
		sofRequest.base64EncodeCert->c_str());



	int nReturn_ = soapSender::SOF_ValidateCert(sofRequest, nResp);
	if (0 == nResp)
	{
		CString strInfo;
		strInfo.Format("SOF_ValidateCert succeed! nResp=%d",nResp);
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_ValidateCert failed! nReturn_=%d,nResp=%d",nReturn_, nResp);
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnDecryptFile()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREDecryptFile sofRequest;
	BOOL bResp = FALSE;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;

	int nReturn_ = soapSender::SOF_DecryptFile(sofRequest, bResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_DecryptFile succeed! bResp=%d",bResp);
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_DecryptFile failed! nReturn_=%d,bResp=%d",nReturn_, bResp);
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnSetSignmethod()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCORESetSignMethod sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.signMethod = SGD_SM1_ECB;

	LOG_INFO("SOF_SetSignMethod:sofRequest.signMethod=%d",sofRequest.signMethod);


	int nReturn_ = soapSender::SOF_SetSignMethod(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_SetSignMethod succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_SetSignMethod failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnGetTimestampinfo()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szTimeStampRep.empty())
	{
		AfxMessageBox("时间戳为空，请先调用分别调用SOF_CreateTimeStampRequest，SOF_CreateTimeStampResponse函数");
		return;
	}
	WS1__SOF_USCOREGetTimeStampInfo sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.tsResponseData = &CEnDecodeClass::StringA2W(g_szTimeStampRep);
	LOG_INFO("SOF_GetTimeStampInfo:sofRequest.tsResponseData=%s",sofRequest.tsResponseData->c_str());

	int nReturn_ = soapSender::SOF_GetTimeStampInfo(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_GetTimeStampInfo succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_GetTimeStampInfo failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnSignDatabyp7()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCORESignDataByP7 sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	std::string szdata("xztzhonghua");
	sofRequest.inData =&CEnDecodeClass::StringA2W(szdata);
	LOG_INFO("SOF_SignDataByP7:sofRequest.inData=%s",sofRequest.inData->c_str());

	int nReturn_ = soapSender::SOF_SignDataByP7(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_SignDataByP7 succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
		g_szP7Sign = szResp;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_SignDataByP7 failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnEncryptFile()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREEncryptFile sofRequest;
	BOOL bResp = FALSE;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;

	int nReturn_ = soapSender::SOF_EncryptFile(sofRequest, bResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_EncryptFile succeed! bResp=%d",bResp);
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_EncryptFile failed! nReturn_=%d,bResp=%d",nReturn_, bResp);
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnSignDataxml()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCORESignDataXML sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	std::string szData("<note><to>George</to><from>John</from><heading>Reminder</heading><body>Don't forget the meeting!</body></note>");
	sofRequest.inData =&CEnDecodeClass::StringA2W(szData);

	LOG_INFO("SOF_SignDataXML:sofRequest.inData=\r\n%s",sofRequest.inData->c_str());

	int nReturn_ = soapSender::SOF_SignDataXML(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_SignDataXML succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);

		g_szXmlCert = szResp;
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_SignDataXML failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}
std::string g_EncryptData;
void CTestCADlg2::OnBnClickedBtnDecryptData()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_EncryptData.empty())
	{
		AfxMessageBox("请先用SOF_EncryptData进行数据加密");
		return;
	}
	WS1__SOF_USCOREDecryptData sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.inData = &CEnDecodeClass::StringA2W(g_EncryptData);

	int nReturn_ = soapSender::SOF_DecryptData(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_DecryptData succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_DecryptData failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnQueryCerttrustlistaltnames()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREQueryCertTrustListAltNames sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;

//	LOG_INFO("SOF_QueryCertTrustListAltNames:sofRequest.tokenId=%s",sofRequest.tokenId->c_str());

	int nReturn_ = soapSender::SOF_QueryCertTrustListAltNames(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_QueryCertTrustListAltNames succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_QueryCertTrustListAltNames failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnGetCertinfo()
{
	// TODO: 在此添加控件通知处理程序代码
	if (g_szbase64Cert.empty())
	{
		AfxMessageBox("请在主界面通过证书导出按钮导出证书");
		return ;
	}
	WS1__SOF_USCOREGetCertInfo sofRequest;
	std::string szResp;

	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.base64EncodeCert = &CEnDecodeClass::StringA2W(g_szbase64Cert);
	sofRequest.type = 1;
	LOG_INFO("SOF_GetCertInfo:sofRequest.base64EncodeCert=%s,\r\nsofRequest.type=%d",
													   sofRequest.base64EncodeCert->c_str(),
													   sofRequest.type);

	int nReturn_ = soapSender::SOF_GetCertInfo(sofRequest, szResp);
	if (0 == nReturn_)
	{
		CString strInfo;
		strInfo.Format("SOF_GetCertInfo succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_GetCertInfo failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}

void CTestCADlg2::OnBnClickedBtnEncryptData()
{
	// TODO: 在此添加控件通知处理程序代码
	WS1__SOF_USCOREEncryptData sofRequest;
	std::string szResp;

	std::string szData("zxcvbn");
	std::string szToken("9877654433");
	//sofRequest.tokenId = &szToken;
	sofRequest.inData = &CEnDecodeClass::StringA2W(szData);

	int nReturn_ = soapSender::SOF_EncryptData(sofRequest, szResp);
	if (0 == nReturn_)
	{
		g_EncryptData = szResp;
		CString strInfo;
		strInfo.Format("SOF_EncryptData succeed! szResp=%s",szResp.c_str());
		AfxMessageBox(strInfo);
	}
	else
	{
		CString strInfo;
		strInfo.Format("SOF_EncryptData failed! nReturn_=%d,szResp=%s",nReturn_, szResp.c_str());
		AfxMessageBox(strInfo);
	}
}
