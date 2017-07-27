#include "StdAfx.h"
#include "ReadUKey.h"

CReadUKey::CReadUKey(void)
{
	m_hDll = NULL;
	m_PSKF_EnumDev = NULL;
	m_PSKF_ConnectDev = NULL;
	m_hDev = NULL;
	m_hApp = NULL;
	m_ulType = 0;

	m_PSKF_RSAPubKeyEncrypt = NULL;
	m_PSKF_RSAPriKeyDecrypt = NULL;
	m_PSKF_ECCDecrypt = NULL;

}

CReadUKey::~CReadUKey(void)
{
	if (NULL != m_hDll)
	{
//		FreeLibrary(m_hDll);
	}
}

void CReadUKey::ClearDLL()
{
	if (NULL != m_hDll)
	{
		FreeLibrary(m_hDll);
	}
}

BOOL CReadUKey::initDll()
{
	std::string szDll ="C:\\Windows\\System32\\ShuttleCsp11_3000GM.dll";

	if (!LoadDLLEx(m_hDll,szDll.c_str()))
	{
		return FALSE;
	}

	//1.设备管理
	if (!DevManageInterfaces())
	{
		return FALSE;
	}

	//2. 访问控制	
	if (!CallControlInterfaces())
	{
		return FALSE;
	}
	//3. 应用管理
	if (!AppsManageInterfaces())
	{
		return FALSE;
	}
    //4. 文件管理
	if (!FileManageInterfaces())
	{
		return FALSE;
	}
	//5. 容器管理
	if (!ContainerManageInterfaces())
	{
		return FALSE;
	}
	//6. 密码服务
	if (!LoadCryptInterfaces())
	{
		return FALSE;
	}

	//其它
	LoadOtherInterfaces();

	return TRUE;
}
BOOL CReadUKey::LoadOtherInterfaces()
{
	if (!GetFunAdress(m_hDll,"SKF_RSAPriKeyDecrypt",(void*&)m_PSKF_RSAPriKeyDecrypt)
		||!GetFunAdress(m_hDll,"SKF_RSAPubKeyEncrypt",(void*&)m_PSKF_RSAPubKeyEncrypt)
		||!GetFunAdress(m_hDll,"SKF_ECCDecrypt",(void*&)m_PSKF_ECCDecrypt))
	{

		return FALSE;
	}

	return TRUE;
}

BOOL CReadUKey::initDll(std::string szDll)
{
	//std::string szDll ="C:\\Windows\\System32\\ShuttleCsp11_3000GM.dll";
    //szDll = "SKFAPI20438.dll";

	if (!LoadDLLEx(m_hDll,szDll.c_str()))
	{
		LOG_ERROR("Import Ukey dll failed ,DLL path=%s",szDll.c_str());
		return FALSE;
	}

	//1.设备管理
	if (!DevManageInterfaces())
	{
		LOG_ERROR("DevManageInterfaces::Import Ukey interfaces failed ,DLL path=%s",szDll.c_str());
		return FALSE;
	}

	//2. 访问控制	
	if (!CallControlInterfaces())
	{
		LOG_ERROR("CallControlInterfaces::Import Ukey interfaces failed ,DLL path=%s",szDll.c_str());
		return FALSE;
	}
	//3. 应用管理
	if (!AppsManageInterfaces())
	{
		LOG_ERROR("AppsManageInterfaces::Import Ukey interfaces failed ,DLL path=%s",szDll.c_str());
		return FALSE;
	}
	//4. 文件管理
	if (!FileManageInterfaces())
	{
		LOG_ERROR("FileManageInterfaces::Import Ukey interfaces failed ,DLL path=%s",szDll.c_str());
		return FALSE;
	}
	//5. 容器管理
	if (!ContainerManageInterfaces())
	{
		LOG_ERROR("ContainerManageInterfaces::Import Ukey interfaces failed ,DLL path=%s",szDll.c_str());
		return FALSE;
	}
	//6. 密码服务
	if (!LoadCryptInterfaces())
	{
		LOG_ERROR("LoadCryptInterfaces::Import Ukey interfaces failed ,DLL path=%s",szDll.c_str());
		return FALSE;
	}

	LoadOtherInterfaces();
	return TRUE;
}

//1.设备管理
BOOL CReadUKey::DevManageInterfaces()
{
	if (!GetFunAdress(m_hDll,"SKF_WaitForDevEvent",(void*&)m_PSKF_WaitForDevEvent)
		||!GetFunAdress(m_hDll,"SKF_CancelWaitForDevEvent",(void*&)m_PSKF_CancelWaitForDevEvent)
		||!GetFunAdress(m_hDll,"SKF_EnumDev",(void*&)m_PSKF_EnumDev)
		||!GetFunAdress(m_hDll,"SKF_ConnectDev",(void*&)m_PSKF_ConnectDev)
		||!GetFunAdress(m_hDll,"SKF_DisConnectDev",(void*&)m_PSKF_DisConnectDev)
		||!GetFunAdress(m_hDll,"SKF_GetDevState",(void*&)m_PSKF_GetDevState)
		||!GetFunAdress(m_hDll,"SKF_SetLabel",(void*&)m_PSKF_SetLabel)
		||!GetFunAdress(m_hDll,"SKF_GetDevInfo",(void*&)m_PSKF_GetDevInfo)
		||!GetFunAdress(m_hDll,"SKF_LockDev",(void*&)m_PSKF_LockDev)
		||!GetFunAdress(m_hDll,"SKF_UnlockDev",(void*&)m_PSKF_UnlockDev))
	{

		return FALSE;
	}

	return TRUE;
}

/************************************************************************/
/*  2. 访问控制				                                            */
/*	SKF_ChangeDevAuthKey												*/
/*	SKF_DevAuth															*/
/*	SKF_ChangePIN														*/
/*	SKF_GetPINInfo														*/
/*	SKF_VerifyPIN														*/
/*	SKF_UnblockPIN														*/
/*	SKF_ClearSecureState												*/
/************************************************************************/
BOOL CReadUKey::CallControlInterfaces()
{
	if (!GetFunAdress(m_hDll,"SKF_ChangeDevAuthKey",(void*&)m_PSKF_ChangeDevAuthKey)
		||!GetFunAdress(m_hDll,"SKF_DevAuth",(void*&)m_PSKF_DevAuth)
		||!GetFunAdress(m_hDll,"SKF_ChangePIN",(void*&)m_PSKF_ChangePIN)
		||!GetFunAdress(m_hDll,"SKF_GetPINInfo",(void*&)m_PSKF_GetPINInfo)
		||!GetFunAdress(m_hDll,"SKF_VerifyPIN",(void*&)m_PSKF_VerifyPIN)
		||!GetFunAdress(m_hDll,"SKF_UnblockPIN",(void*&)m_PSKF_UnblockPIN)
		||!GetFunAdress(m_hDll,"SKF_ClearSecureState",(void*&)m_PSKF_ClearSecureState))
	{
		return FALSE;
	}

	return TRUE;
}

/************************************************************************/
/*  3. 应用管理				                                            */
/*	SKF_CreateApplication												*/
/*	SKF_EnumApplication													*/
/*	SKF_DeleteApplication												*/
/*	SKF_OpenApplication													*/
/*	SKF_CloseApplication												*/
/************************************************************************/
BOOL CReadUKey::AppsManageInterfaces()
{
	if (!GetFunAdress(m_hDll,"SKF_CreateApplication",(void*&)m_PSKF_CreateApplication)
		||!GetFunAdress(m_hDll,"SKF_EnumApplication",(void*&)m_PSKF_EnumApplication)
		||!GetFunAdress(m_hDll,"SKF_DeleteApplication",(void*&)m_PSKF_DeleteApplication)
		||!GetFunAdress(m_hDll,"SKF_OpenApplication",(void*&)m_PSKF_OpenApplication)
		||!GetFunAdress(m_hDll,"SKF_CloseApplication",(void*&)m_PSKF_CloseApplication))
	{
		return FALSE;
	}

	return TRUE;
}

/************************************************************************/
/*  4. 文件管理				                                            */
/*	SKF_CreateFile														*/
/*	SKF_DeleteFile														*/
/*	SKF_EnumFiles														*/
/*	SKF_GetFileInfo														*/
/*	SKF_ReadFile														*/
/*	SKF_WriteFile														*/
/************************************************************************/
BOOL CReadUKey::FileManageInterfaces()
{
	if (!GetFunAdress(m_hDll,"SKF_CreateFile",(void*&)m_PSKF_CreateFile)
		||!GetFunAdress(m_hDll,"SKF_DeleteFile",(void*&)m_PSKF_DeleteFile)
		||!GetFunAdress(m_hDll,"SKF_EnumFiles",(void*&)m_PSKF_EnumFiles)
		||!GetFunAdress(m_hDll,"SKF_GetFileInfo",(void*&)m_PSKF_GetFileInfo)
		||!GetFunAdress(m_hDll,"SKF_ReadFile",(void*&)m_PSKF_ReadFile)
		||!GetFunAdress(m_hDll,"SKF_WriteFile",(void*&)m_PSKF_WriteFile))
	{
		return FALSE;
	}

	return TRUE;
}

/************************************************************************/
/*  5. 容器管理				                                            */
/*	SKF_CreateContainer													*/
/*	SKF_DeleteContainer													*/
/*	SKF_OpenContainer													*/
/*	SKF_CloseContainer													*/
/*	SKF_EnumContainer													*/
/*  SKF_GetContainerType                                            */
/*  SKF_ExportCertificate                                            */
/*  SKF_ImportCertificate                                            */
/************************************************************************/
BOOL CReadUKey::ContainerManageInterfaces()
{
	if (!GetFunAdress(m_hDll,"SKF_CreateContainer",(void*&)m_PSKF_CreateContainer)
		||!GetFunAdress(m_hDll,"SKF_OpenContainer",(void*&)m_PSKF_OpenContainer)
		||!GetFunAdress(m_hDll,"SKF_DeleteContainer",(void*&)m_PSKF_DeleteContainer)
		||!GetFunAdress(m_hDll,"SKF_CloseContainer",(void*&)m_PSKF_CloseContainer)
		||!GetFunAdress(m_hDll,"SKF_EnumContainer",(void*&)m_PSKF_EnumContainer)
		||!GetFunAdress(m_hDll,"SKF_GetContainerType",(void*&)m_PSKF_GetContainerType)
		||!GetFunAdress(m_hDll,"SKF_ExportCertificate",(void*&)m_PSKF_ExportCertificate)
		||!GetFunAdress(m_hDll,"SKF_ImportCertificate",(void*&)m_PSKF_ImportCertificate))
	{
		return FALSE;
	}

	return TRUE;
}

/************************************************************************/
/*  6. 密码服务				                                            */
/*	SKF_GetRandom														*/
/*	SKF_GenExtRSAKey													*/
/*	SKF_GenRSAKeyPair													*/
/*	SKF_ImportRSAKeyPair												*/
/*	SKF_RSASignData														*/
/*	SKF_RSAVerify														*/
/*	SKF_RSAExportSessionKey												*/
/*	SKF_ExtRSAPubKeyOperation											*/
/*	SKF_ExtRSAPriKeyOperation											*/
/*	SKF_GenECCKeyPair													*/
/*	SKF_ImportECCKeyPair												*/
/*	SKF_ECCSignData														*/
/*	SKF_ECCVerify														*/
/*	SKF_ECCExportSessionKey												*/
/*	SKF_ExtECCEncrypt													*/
/*	SKF_ExtECCDecrypt													*/
/*	SKF_ExtECCSign														*/
/*	SKF_ExtECCVerify													*/
/*	SKF_ExportPublicKey													*/
/*	SKF_ImportSessionKey												*/
/*	SKF_SetSymmKey														*/
/*	SKF_EncryptInit														*/
/*	SKF_Encrypt															*/
/*	SKF_EncryptUpdate													*/
/*	SKF_EncryptFinal													*/
/*	SKF_DecryptInit														*/
/*	SKF_Decrypt															*/
/*	SKF_DecryptUpdate													*/
/*	SKF_DecryptFinal													*/
/*	SKF_DegistInit														*/
/*	SKF_Degist															*/
/*	SKF_DegistUpdate													*/
/*	SKF_DegistFinal														*/
/*	SKF_MACInit															*/
/*	SKF_MAC																*/
/*	SKF_MACUpdate														*/
/*	SKF_MACFinal														*/
/************************************************************************/
BOOL CReadUKey::LoadCryptInterfaces()
{
	if (!GetFunAdress(m_hDll,"SKF_GenRandom",(void*&)m_PSKF_GenRandom)
		||!GetFunAdress(m_hDll,"SKF_GenExtRSAKey",(void*&)m_PSKF_GenExtRSAKey)
		||!GetFunAdress(m_hDll,"SKF_GenRSAKeyPair",(void*&)m_PSKF_GenRSAKeyPair)
		||!GetFunAdress(m_hDll,"SKF_ImportRSAKeyPair",(void*&)m_PSKF_ImportRSAKeyPair)
		||!GetFunAdress(m_hDll,"SKF_RSASignData",(void*&)m_PSKF_RSASignData)
		||!GetFunAdress(m_hDll,"SKF_RSAVerify",(void*&)m_PSKF_RSAVerify)
		||!GetFunAdress(m_hDll,"SKF_RSAExportSessionKey",(void*&)m_PSKF_RSAExportSessionKey)
		||!GetFunAdress(m_hDll,"SKF_ExtRSAPubKeyOperation",(void*&)m_PSKF_ExtRSAPubKeyOperation)
		||!GetFunAdress(m_hDll,"SKF_ExtRSAPriKeyOperation",(void*&)m_PSKF_ExtRSAPriKeyOperation)
		||!GetFunAdress(m_hDll,"SKF_GenECCKeyPair",(void*&)m_PSKF_GenECCKeyPair)
		||!GetFunAdress(m_hDll,"SKF_ImportECCKeyPair",(void*&)m_PSKF_ImportECCKeyPair)
		||!GetFunAdress(m_hDll,"SKF_ECCSignData",(void*&)m_PSKF_ECCSignData)
		||!GetFunAdress(m_hDll,"SKF_ECCVerify",(void*&)m_PSKF_ECCVerify)
		||!GetFunAdress(m_hDll,"SKF_ECCExportSessionKey",(void*&)m_PSKF_ECCExportSessionKey)
		||!GetFunAdress(m_hDll,"SKF_ExtECCEncrypt",(void*&)m_PSKF_ExtECCEncrypt)
		||!GetFunAdress(m_hDll,"SKF_ExtECCDecrypt",(void*&)m_PSKF_ExtECCDecrypt)
		||!GetFunAdress(m_hDll,"SKF_ExtECCSign",(void*&)m_PSKF_ExtECCSign)
		||!GetFunAdress(m_hDll,"SKF_ExtECCVerify",(void*&)m_PSKF_ExtECCVerify)
		||!GetFunAdress(m_hDll,"SKF_ExportPublicKey",(void*&)m_PSKF_ExportPublicKey)
		||!GetFunAdress(m_hDll,"SKF_ImportSessionKey",(void*&)m_PSKF_ImportSessionKey)
		||!GetFunAdress(m_hDll,"SKF_SetSymmKey",(void*&)m_PSKF_SetSymmKey)
		||!GetFunAdress(m_hDll,"SKF_EncryptInit",(void*&)m_PSKF_EncryptInit)
		||!GetFunAdress(m_hDll,"SKF_Encrypt",(void*&)m_PSKF_Encrypt)
		||!GetFunAdress(m_hDll,"SKF_EncryptUpdate",(void*&)m_PSKF_EncryptUpdate)
		||!GetFunAdress(m_hDll,"SKF_EncryptFinal",(void*&)m_PSKF_EncryptFinal)
		||!GetFunAdress(m_hDll,"SKF_DecryptInit",(void*&)m_PSKF_DecryptInit)
		||!GetFunAdress(m_hDll,"SKF_Decrypt",(void*&)m_PSKF_Decrypt)
		||!GetFunAdress(m_hDll,"SKF_DecryptUpdate",(void*&)m_PSKF_DecryptUpdate)
		||!GetFunAdress(m_hDll,"SKF_DecryptFinal",(void*&)m_PSKF_DecryptFinal)
		||!GetFunAdress(m_hDll,"SKF_DigestInit",(void*&)m_PSKF_DigestInit)
		||!GetFunAdress(m_hDll,"SKF_Digest",(void*&)m_PSKF_Digest)
		||!GetFunAdress(m_hDll,"SKF_DigestUpdate",(void*&)m_PSKF_DigestUpdate)
		||!GetFunAdress(m_hDll,"SKF_DigestFinal",(void*&)m_PSKF_DigestFinal)
		||!GetFunAdress(m_hDll,"SKF_MacInit",(void*&)m_PSKF_MacInit)
		||!GetFunAdress(m_hDll,"SKF_Mac",(void*&)m_PSKF_Mac)
		||!GetFunAdress(m_hDll,"SKF_MacUpdate",(void*&)m_PSKF_MacUpdate)
		||!GetFunAdress(m_hDll,"SKF_MacFinal",(void*&)m_PSKF_MacFinal)
		)
	{
		return FALSE;
	}

	return TRUE;
}


BOOL CReadUKey::LoadDLLEx(HMODULE&	hDll,std::string sDLLName)
{
	hDll =	LoadLibrary(sDLLName.c_str());
	if (NULL == hDll){
		LOG_ERROR("Initialize Load %s Failed ErrorCode = %d",sDLLName.c_str(), GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL CReadUKey::GetFunAdress(HMODULE hDll,char* csFunName,void*& pFunAdress)
{
	//if (NULL != pFunAdress)
	//{
	//	return TRUE;
	//}

	BOOL	bRet		= FALSE;
	pFunAdress = (PVOID)GetProcAddress(hDll,csFunName);
	if (NULL == pFunAdress)
	{
		LOG_ERROR("Initialize GetProcAddress %s failed",csFunName);
		return bRet;
	}

	return TRUE;
}


ULONG CReadUKey::GetDevInfo(DEVHANDLE *phDev)
{
	ULONG rv=0;

	char *pbDevList= 0;
	ULONG ulDevListLen = 0;

	rv = m_PSKF_EnumDev(1,pbDevList,&ulDevListLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EnumDev",rv);
		return rv;		
	}

	if(ulDevListLen <2)
	{
		LOG_ERROR("No Device!\n");
		return -1;
	}

	pbDevList = (char *)malloc(ulDevListLen);
	if(pbDevList == NULL)
	{
		LOG_ERROR("Memory Error!");
		return -1;
	}
	rv = m_PSKF_EnumDev(1,pbDevList,&ulDevListLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EnumDev",rv,pbDevList);
		return rv;		
	}

	char *pp = pbDevList;
	while(pbDevList+ulDevListLen - pp)
	{
		if(strlen(pp))
		{
			printf("find Device %s\n",pp);
			pp+=strlen(pp);
		}
		else
		{
			pp++;
		}
	}

	pp = 0;


	DEVHANDLE hDev;

	rv = m_PSKF_ConnectDev(pbDevList,&hDev);
	if(rv)
	{
		PrintError("SKF_ConnectDev",rv,pbDevList);
		return rv;	

	}
	LOG_INFO("Connect Device %s\n",pbDevList);
	*phDev = hDev;

	if(pbDevList)
		free(pbDevList);

	return SAR_OK;

}

//ULONG CReadUKey::GetContainerFromDevName(ReadCertInfo* pRCI,HCONTAINER& hCon)
//{
//	ULONG rv=0;
//
//	char *pbDevList= 0;
//	ULONG ulDevListLen = 0;
//
//	rv = m_PSKF_EnumDev(1,pbDevList,&ulDevListLen);
//	if(rv != SAR_OK)
//	{
//		PrintError("SKF_EnumDev",rv);
//		return rv;		
//	}
//
//	if(ulDevListLen <2)
//	{
//		LOG_ERROR("No Device!\n");
//		return -1;
//	}
//
//	pbDevList = (char *)malloc(ulDevListLen);
//	if(pbDevList == NULL)
//	{
//		LOG_ERROR("Memory Error!");
//		return -1;
//	}
//	rv = m_PSKF_EnumDev(1,pbDevList,&ulDevListLen);
//	if(rv != SAR_OK)
//	{
//		PrintError("SKF_EnumDev",rv,pbDevList);
//		return rv;		
//	}
//
//	char *pp = pbDevList;
//	while(pbDevList+ulDevListLen - pp)
//	{
//		if(strlen(pp))
//		{
//			if (0 == pRCI->m_szDevName.compare(pp))
//			{
//				DEVHANDLE hDev;
//				rv = m_PSKF_ConnectDev(pp,&hDev);
//				if(rv)
//				{
//					PrintError("SKF_ConnectDev",rv,pbDevList);
//					return rv;
//				}
//				rv = GetContainerFromAppName(hDev,pRCI,hCon);
//				break;
//			}
//			
//
//			pp+=strlen(pp);
//		}
//		else
//		{
//			pp++;
//		}
//	}
//
//	pp = 0;
//
//	if(pbDevList)
//		free(pbDevList);
//
//	return SAR_OK;
//
//}

//ULONG CReadUKey::GetContainerFromAppName(DEVHANDLE hDev,ReadCertInfo* pRCI,HCONTAINER& hCon)
//{
//	DWORD rv = 0;
//
//	char *szAppList = NULL;
//	ULONG ulAppListLen = 0;
//
//	rv= m_PSKF_EnumApplication(hDev,szAppList,&ulAppListLen);
//	if(rv)
//	{
//		PrintError("SKF_EnumApplication",rv);
//		return rv;
//	}
//
//	if(ulAppListLen < 2)
//	{
//		LOG_ERROR("No Application!\n");
//		return -1;
//	}
//	szAppList = (char *)malloc(ulAppListLen);
//	rv = m_PSKF_EnumApplication(hDev,szAppList,&ulAppListLen);
//	if(rv)
//	{
//		PrintError("SKF_EnumApplication",rv,szAppList);
//		return rv;
//	}
//
//	char *pp = szAppList;
//	while(szAppList+ulAppListLen - pp)
//	{
//		if(strlen(pp))
//		{
//			if (0 == pRCI->m_szAppName.compare(pp))
//			{
//				HAPPLICATION phApp;
//				rv = m_PSKF_OpenApplication(hDev,pp,&phApp);
//				if (rv)
//				{
//					PrintError("SKF_OpenApplication",rv,szAppList);
//					return rv;
//				}
//				else
//				{
//					rv = GetContainerFromContainerName(hDev,phApp,pRCI,hCon);
//					break;
//				}
//			}
//			
//
//			pp+=strlen(pp);
//		}
//		else
//		{
//			pp++;
//		}
//	}
//
//
//
//
//	if(szAppList)
//	{
//		free(szAppList);
//		szAppList = NULL;
//	}
//
//	return SAR_OK;
//}
//ULONG CReadUKey::GetContainerFromContainerName(DEVHANDLE hDev,HAPPLICATION phApp,ReadCertInfo* pRCI,HCONTAINER& hCon)
//{
//	char *szConList = NULL;
//	ULONG ulConListLen = 0;
//
//	ULONG rv= m_PSKF_EnumContainer(phApp,szConList,&ulConListLen);
//	if(rv)
//	{
//		PrintError("m_PSKF_EnumContainer",rv);
//		return rv;
//	}
//
//	if(ulConListLen < 2)
//	{
//		LOG_ERROR("No Container!\n");
//		return -1;
//	}
//	szConList = (char *)malloc(ulConListLen);
//	rv = m_PSKF_EnumContainer(phApp,szConList,&ulConListLen);
//	if(rv)
//	{
//		PrintError("m_PSKF_EnumContainer",rv,szConList);
//		return rv;
//	}
//
//	char *pp = szConList;
//	while(szConList+ulConListLen - pp)
//	{
//		if(strlen(pp))
//		{
//			if (0 == pRCI->m_szContainerName.compare(pp))
//			{
//				ULONG rv = m_PSKF_OpenContainer(phApp,pp,&hCon);
//				if (rv)
//				{
//					PrintError("m_PSKF_OpenContainer",rv);
//					return rv;
//				}
//				else
//				{
//					break;
//				}
//
//			}
//			
//			pp+=strlen(pp);
//		}
//		else
//		{
//			pp++;
//		}
//	}
//
//	if (szConList)
//	{
//		free(szConList);
//	}
//
//	return rv;
//}

ULONG CReadUKey::GetDevInfo2(std::vector<ReadCertInfo>& vecCert)
{
	ULONG rv=0;

	char *pbDevList= 0;
	ULONG ulDevListLen = 0;

	rv = m_PSKF_EnumDev(1,pbDevList,&ulDevListLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EnumDev",rv);
		return rv;		
	}

	if(ulDevListLen <2)
	{
		LOG_ERROR("No Device!\n");
		return -1;
	}

	pbDevList = (char *)malloc(ulDevListLen);
	if(pbDevList == NULL)
	{
		LOG_ERROR("Memory Error!");
		return -1;
	}
	rv = m_PSKF_EnumDev(1,pbDevList,&ulDevListLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EnumDev",rv,pbDevList);
		return rv;		
	}

	char *pp = pbDevList;
	while(pbDevList+ulDevListLen - pp)
	{
		if(strlen(pp))
		{
			printf("find Device %s\n",pp);
			//读入设备中的证书信息
			DEVHANDLE hDev;
			rv = m_PSKF_ConnectDev(pp,&hDev);
			if(rv)
			{
				PrintError("SKF_ConnectDev",rv);
				pp+=strlen(pp);
				continue;
			}
			LOG_INFO("Connect Device %s\n",pp);
			m_hDev = hDev;
			rv = EnumCertsFromDev(hDev,vecCert,pp);
			if (rv)
			{
				pp+=strlen(pp);
				continue;
			}

			pp+=strlen(pp);
		}
		else
		{
			pp++;
		}
	}

	pp = 0;

	if(pbDevList)
		free(pbDevList);

	return SAR_OK;

}

ULONG CReadUKey::AppManage(DEVHANDLE hDev,HAPPLICATION *phApp)
{
	DWORD rv = 0;

	DEVINFO  devInfo;
	memset((char *)&devInfo,0x00,sizeof(DEVINFO));

	rv = m_PSKF_GetDevInfo(hDev,&devInfo);
	if(rv)
	{
		PrintError("SKF_GetDevInfo",rv);
		return rv;	

	}
	DWORD dwAuthAlgId = devInfo.DevAuthAlgId;
	HANDLE hKey;
	unsigned char pbAuthKey[16]={0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};    //初始的设备认证密钥,可以修改

	////////////////////////////////////////////////////
	//这一点计算设备认证值时最好是不要使用这种方式，而是使用其他的方法如使用其它的设备计算结果
	rv = m_PSKF_SetSymmKey(hDev,pbAuthKey,dwAuthAlgId,&hKey);
	if(rv)
	{
		PrintError("SKF_SetSymmKey",rv);
		return rv;
	}
	BLOCKCIPHERPARAM EncryptParam;
	memset((char *)&EncryptParam,0x00,sizeof(BLOCKCIPHERPARAM));
	rv = m_PSKF_EncryptInit(hKey,EncryptParam);
	if(rv)
	{
		PrintError("SKF_EncryptInit",rv);
		return rv;
	}

	unsigned char pbRandom[32]={0},pbAuthValue[32]={0};
	ULONG ulAuthValueLen =32;

	rv = m_PSKF_GenRandom(hDev,pbRandom,8);
	if(rv)
	{
		PrintError("SKF_GenRandom",rv);
		return rv;
	}

	rv = m_PSKF_Encrypt(hKey,pbRandom,16,pbAuthValue,&ulAuthValueLen);
	if(rv)
	{
		PrintError("SKF_Encrypt",rv);
		return rv;
	}

	rv = m_PSKF_DevAuth(hDev,pbAuthValue,ulAuthValueLen);
	if(rv)
	{
		PrintError("SKF_DevAuth",rv);
		return rv;
	}

	char *szAppList = NULL;
	ULONG ulAppListLen = 0;

	rv= m_PSKF_EnumApplication(hDev,szAppList,&ulAppListLen);
	if(rv)
	{
		PrintError("SKF_EnumApplication",rv);
		return rv;
	}

	if(ulAppListLen < 2)
	{
		LOG_ERROR("No Application!\n");
		return -1;
	}
	szAppList = (char *)malloc(ulAppListLen);
	rv = m_PSKF_EnumApplication(hDev,szAppList,&ulAppListLen);
	if(rv)
	{
		PrintError("SKF_EnumApplication",rv,szAppList);
		return rv;
	}
	printf("Find Application：%s\n",szAppList);

	///////现在设备中就一个应用，
	rv = m_PSKF_DeleteApplication(hDev,szAppList);
	if(rv)
	{
		PrintError("SKF_DeleteApplication",rv,szAppList);
		return rv;
	}

	LOG_INFO("Delete Application %s succeed!\n",szAppList);

	char szAppName[32]={0};
	memcpy(szAppName,"EnterSafe",9);
	rv = m_PSKF_CreateApplication(hDev,szAppName,"rockey",6,"123456",6,SECURE_USER_ACCOUNT,phApp);
	if(rv)
	{
		PrintError("SKF_CreateApplication",rv,szAppList);
		return rv;
	}

	LOG_INFO("Create Application %s succeed!\n",szAppName);
	if(szAppList)
	{
		free(szAppList);
		szAppList = NULL;
	}

	return SAR_OK;
}


ULONG CReadUKey::RasKeyPairTest(DEVHANDLE hDev,HAPPLICATION hApp)
{

	ULONG rv = SAR_OK,ulRetryCount =0;
	HCONTAINER hCon;
	char szContainer[64]={0};

	rv = m_PSKF_VerifyPIN(hApp,USER_TYPE,"123456",&ulRetryCount);
	if(rv)
	{
		PrintError("SKF_VerifyPIN",rv);
		return rv;
	}

	memcpy(szContainer,"RSA_Container",13);

	rv = m_PSKF_CreateContainer(hApp,szContainer,&hCon);
	if(rv)
	{
		PrintError("SKF_CreateContainer",rv);
		return rv;

	}

	RSAPUBLICKEYBLOB RsaPubKey;

	rv = m_PSKF_GenRSAKeyPair(hCon,1024,&RsaPubKey);
	if(rv)
	{
		PrintError("SKF_GenRSAKeyPair",rv);
		return rv;
	}

	unsigned char pbData[1024]={0},pbDigest[32]={0},pbSignData[128]={0};
	ULONG ulDataLen = 1024,ulDigestLen = 32,ulSignDataLen = 128;

	ULONG i = 0;
	for(i =0;i<1024;i++)
	{
		pbData[i] = (unsigned char)((i*4+3)%256);
	}

	HANDLE hHash;

	rv = m_PSKF_DigestInit(hDev,SGD_SHA1,NULL,NULL,0,&hHash);
	if(rv)
	{
		PrintError("SKF_DigestInit",rv);
		return rv;
	}

	rv = m_PSKF_Digest(hHash,pbData,ulDataLen,pbDigest,&ulDigestLen);
	if(rv)
	{
		PrintError("SKF_Digest",rv);
		return rv;
	}

	LOG_DEBUG("the Digest of the Data is :");
	for(i=0;i<ulDigestLen;i++)
	{
		LOG_DEBUG("0x%02x ",pbDigest[i]);
	}


	rv = m_PSKF_RSASignData(hCon,pbDigest,ulDigestLen,pbSignData,&ulSignDataLen);
	if(rv)
	{
		PrintError("SKF_RSASignData",rv);
		return rv;
	}

	LOG_DEBUG("the signValue of the Data is :\n");
	for(i=0;i<ulSignDataLen;i++)
	{
		LOG_DEBUG("0x%02x ",pbSignData[i]);
	}

	LOG_DEBUG("\n");

	rv = m_PSKF_RSAVerify(hDev,&RsaPubKey,pbDigest,ulDigestLen,pbSignData,ulSignDataLen);
	if(rv)
	{
		PrintError("SKF_RSAVerify",rv);
		return rv;
	}
	LOG_INFO("verify SignValue is succeed!\n");

	return SAR_OK;

}

ULONG CReadUKey::ImportRSAKeyPairTest(DEVHANDLE hDev,HAPPLICATION hApp)
{

	ULONG rv;

	RSAPUBLICKEYBLOB pPubKey;
	unsigned char pbWrappedKey[128]={0},pbEncryptedData[2048]={0},pbData[2048]={0};
	ULONG ulWrappedKeyLen=256,ulDataLen=0,ulEncryptedDataLen=2048,ulPubKeyLen = 0;
	BLOCKCIPHERPARAM EncryptParam;
	int offset=0;

	char szConName[64]={0};
	HCONTAINER hCon;
	memcpy(szConName,"RSA_Container",13);

	rv = m_PSKF_OpenContainer(hApp,szConName,&hCon);
	if(rv)
	{
		PrintError("SKF_OpenContainer",rv);
		return rv;
	}

	HANDLE hSessionKey;
	ulPubKeyLen = sizeof(pPubKey);

	//导出签名公钥
	rv = m_PSKF_ExportPublicKey(hCon,TRUE,(unsigned char *)&pPubKey,&ulPubKeyLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_ExportPublicKey",rv);
		return rv;
	}

	//RSA生成并导出会话密钥
	rv = m_PSKF_RSAExportSessionKey (hCon,SGD_SM1_ECB,&pPubKey,pbWrappedKey,&ulWrappedKeyLen,&hSessionKey);
	if(rv != SAR_OK)
	{
		PrintError("SKF_RSAExportSessionKey",rv);
		return rv;
	}

	memcpy(pbData,"\x30\x82\x02\x5D\x02\x01\x00\x02\x81\x81\x00\xD8\x6D\x24\x88\x39\x79\x0B\x3F\xDF\x65\x7C\x19\x28\x06\x58\x2B\x7B\x78\xC1\xF4\x8B\x0B\x26\x57\x6A\xD0\x26\x4B\x5F\x0A\x3A\x10\x6C\x60\x27\x48\x26\x78\xF8\x7D\x52\x45\x36\xC0\x2A\xAA\xA9\xBC\xED\xD1\x5A\x5A\x2F\xBD\xEC\xFD\x66\x37\xBA\x95\xD7\x9A\x0A\xEE\xA4\x13\x7E\x74\xB5\x83\xE2\x4E\xE3\x40\x24\x88\xCA\x61\x09\x3B\x6B\x59\xEA\xB8\x0A\x05\x8D\xCF\x52\x49\x0D\x7A\x1E\xE3\x52\xDB\xD8\x64\x0A\x3E\x45\x25\xA9\x61\xA7\x9E\xC2\xD9\xEE\xA1\x88\xC7\x2F\x41\x86\x8C\xD8\x80\x08\x14\x9D\x88\x55\x67\xCC\x92\x81\xF5\x02\x03\x01\x00\x01\x02\x81\x81\x00\x94\x90\xF7\x8E\xFB\xC4\xF7\xCF\xF4\xCE\x79\x8D\xDB\x47\xDF\xA6\x99\xAF\x9F\x94\xFB\x0D\xC0\x58\x29\xDE\x91\x2B\x14\x26\xB5\x0D\x29\x18\x28\x5F\x02\xE9\xEF\xCA\x37\x7B\x83\xC6\x0E\x83\xF0\xD8\xDC\x77\xE6\x0A\x1A\xD3\xC9\xA7\x79\x4F\xB0\x29\xC4\x42\xDE\x55\x07\xDB\xB7\xB8\x39\x4C\x28\xF7\x74\x56\x12\x2C\x0F\x03\xCF\x48\x45\xCE\xCF\x59\xCE\x5D\x6D\x0F\x0F\xFB\xBE\xD1\x6C\x1B\x88\x2D\x5B\x2E\x0D\x4B\x3F\xE7\x29\x13\x4E\x77\xFD\x50\xD8\xBA\xF3\xCD\x35\x91\x81\x21\xE8\x14\xC4\x35\xD2\xB6\x24\xA8\xC3\x03\x5A\x81\x02\x41\x00\xEF\xF4\x9F\xEC\x35\x98\x5C\xC5\x4C\xE3\x9B\x2F\x26\x7A\x93\x21\xC8\xBF\x53\x21\x0D\xA1\x34\x91\xF5\x69\xE4\x00\x90\x9F\x80\x1E\x5B\x34\x96\x66\xB5\x1F\x80\x7B\x64\x7D\x84\x6E\xA1\xD3\x3C\xEB\xC1\x10\x2E\x4D\x32\xA0\x3F\xD5\x2C\x16\x35\x88\x67\x67\x5B\xC9\x02\x41\x00\xE6\xE5\xC3\x43\xDE\x1A\xFD\x4F\xB2\x76\xA1\x3C\xDC\xDF\x93\x01\xC6\x58\x47\xEB\xAC\x12\x11\x8F\x80\xE9\x00\x79\x78\x85\xAB\xC4\x69\x85\xCE\xB2\xF4\x80\xBF\x91\x40\x09\xCC\xF2\x9B\x32\xB1\xDF\xB3\xAB\x26\x4A\x4B\x21\x8F\xC8\xC5\x29\xCA\xA8\xCA\xBA\xF2\xCD\x02\x41\x00\x91\x94\x77\xA6\x26\x8A\x0E\xD6\xC1\x24\x61\xD5\x44\x62\x1F\x7B\xE2\xC0\x79\x1D\xD7\x98\x13\x3D\xEE\x87\xD5\x05\xA6\xB8\xAE\x51\x3C\x82\x76\x31\x4F\xF8\x11\xCA\x4B\\
		\x18\x7F\xCD\x63\x2E\xB6\x8A\x4D\xF2\x94\x34\xCF\xDF\x3B\x7B\x08\xA9\x5C\xC7\x29\xFD\x22\x49\x02\x40\x61\xEE\xF0\x2C\x58\x07\x50\x8B\xBE\x21\x2C\xF0\x58\xAA\x87\x7A\xC8\x3A\xE7\x7E\x61\x44\x64\xA8\x5E\x3F\xF5\x90\x8F\xFA\xFA\x48\xDB\x8D\x02\x87\xCA\xC6\xD4\xF9\xF1\x94\x76\x96\x2C\x17\x8B\x74\x5B\x8B\x6B\x39\x35\xB6\xAD\x7A\xB5\x8D\xAD\x44\x7C\x80\x60\xBD\x02\x40\x7A\xE3\x7A\xD8\x86\xF9\x2A\x1A\x8A\xE0\xEA\xB5\xD3\x62\x8E\xA7\x58\x08\x6C\x4D\x6B\x30\x5E\xFF\x06\xAC\x09\x48\x69\x8B\xDC\x9E\x16\x35\x65\x1F\x18\x62\xD7\xBF\x21\x54\x77\x32\x2E\xAA\x3D\x89\x0C\xD2\xFA\x30\xA0\x77\xD9\xB5\xD4\x5B\xFB\x99\x41\x3E\x09\xA5",1248);
		ulDataLen = 1248;


	EncryptParam.IVLen = 0;
	EncryptParam.PaddingType = 1;
	rv = m_PSKF_EncryptInit(hSessionKey,EncryptParam);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EncryptInit",rv);
		return rv;
	}

	//进行数据加密
	rv = m_PSKF_Encrypt(hSessionKey,pbData,ulDataLen,pbEncryptedData,&ulEncryptedDataLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_Encrypt",rv);
		return rv;
	}	

	rv = m_PSKF_ImportRSAKeyPair(hCon,SGD_SM1_ECB,pbWrappedKey,ulWrappedKeyLen,pbEncryptedData,ulEncryptedDataLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_ImportRSAKeyPair",rv);
		return rv;
	}
	LOG_INFO("Import RSAKeyPair Succeed!\n");

	return SAR_OK;

}

ULONG CReadUKey::SM2KeyPairTest(DEVHANDLE hDev,HAPPLICATION hApp)
{

	ULONG rv = SAR_OK,ulRetryCount =0;
	HCONTAINER hCon;
	char szContainer[64]={0};

	rv = m_PSKF_VerifyPIN(hApp,USER_TYPE,"123456",&ulRetryCount);
	if(rv)
	{
		PrintError("SKF_VerifyPIN",rv);
		return rv;
	}

	memcpy(szContainer,"SM2_Container",13);

	rv = m_PSKF_CreateContainer(hApp,szContainer,&hCon);
	if(rv)
	{
		PrintError("SKF_CreateContainer",rv);
		return rv;

	}

	ECCPUBLICKEYBLOB EccPubKey;

	rv = m_PSKF_GenECCKeyPair(hCon,SGD_SM2_1,&EccPubKey);
	if(rv)
	{
		PrintError("SKF_GenECCKeyPair",rv);
		return rv;
	}

	unsigned char pbData[1024]={0},pbDigest[32]={0},pbSignData[128]={0};
	ULONG ulDataLen = 1024,ulDigestLen = 32,ulSignDataLen = 128;
	ULONG i =0;
	for(i =0;i<1024;i++)
	{
		pbData[i] = (unsigned char )((i*4+3)%256);
	}

	HANDLE hHash;
	unsigned char userId[32]={0};
	ULONG ulUserIdLen = 0;
	memcpy(userId,"heyalei",7);

	ulUserIdLen = 7;

	rv = m_PSKF_DigestInit(hDev,SGD_SM3,&EccPubKey,userId,ulUserIdLen,&hHash);
	if(rv)
	{
		PrintError("SKF_DigestInit",rv);
		return rv;
	}


	rv = m_PSKF_Digest(hHash,pbData,ulDataLen,pbDigest,&ulDigestLen);
	if(rv)
	{
		PrintError("SKF_Digest",rv);
		return rv;
	}

	LOG_DEBUG("the Digest of the Data is :");
	std::string szMsg;
	for(i=0;i<ulDigestLen;i++)
	{
		LOG_DEBUG("0x%02x ",pbDigest[i]);
	}

	LOG_DEBUG("\n");

	ECCSIGNATUREBLOB EccSignBlob;

	rv = m_PSKF_ECCSignData(hCon,pbDigest,ulDigestLen,&EccSignBlob);
	if(rv)
	{
		PrintError("SKF_ECCSignData",rv);
		return rv;
	}
	memcpy(pbSignData,EccSignBlob.r+32,32);
	memcpy(pbSignData+32,EccSignBlob.s+32,32);
	printf("the signValue of the Data is :\n");
	for(i=0;i<64;i++)
	{
		printf("0x%02x ",pbSignData[i]);
	}

	printf("\n");

	rv = m_PSKF_ECCVerify(hDev,&EccPubKey,pbDigest,ulDigestLen,&EccSignBlob);
	if(rv)
	{
		PrintError("SKF_RSAVerify",rv);
		return rv;
	}
	LOG_INFO("SM2 verify SignValue is succeed!\n");

	return SAR_OK;

}

ULONG CReadUKey::ImportSM2KeyPair_Test(DEVHANDLE hDev,HAPPLICATION hApp)
{
	ULONG rv,rLen;
	ECCPUBLICKEYBLOB pEccSignKey;
	ULONG ulEccPubKeyLen = sizeof(ECCPUBLICKEYBLOB);
	ECCCIPHERBLOB  *pEccCipherBlob=NULL;
	HANDLE hSessionKey;

	PENVELOPEDKEYBLOB pEnvelopedKeyBlob;
	unsigned char pbWrappedKey[32]={0},pbTmpData[1024]={0},pbEncryptedData[1024]={0},pbData[1024]={0};
	ULONG ulWrappedKeyLen=32,ulTmpDataLen=1024,ulEncryptedDataLen=1024;
	BLOCKCIPHERPARAM EncryptParam;
	int offset=0;


	// 	ECCPRIVATEKEYBLOB pEccPriBlb = { 256,{ \
	// 		0x40,0x00,0x14,0x24,0x83,0x02,0x14,0x20,0x42,0x88,0x02,0x4A,0x10,0x14,0x80,0x00,0x02,0x1C,0x00,0x09,0x83,0x58,0x21,0xAC,0x80,0x00,0xA0,0x13,0x11,0x00,0xA8,0x59, \
	// 		0x40,0x00,0x14,0x24,0x83,0x02,0x14,0x20,0x42,0x88,0x02,0x4A,0x10,0x14,0x80,0x00,0x02,0x1C,0x00,0x09,0x83,0x58,0x21,0xAC,0x80,0x00,0xA0,0x13,0x11,0x00,0xA8,0x59
	// 	}};

	ECCPRIVATEKEYBLOB pEccPriBlb = { 256,{ \
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
		0x40,0x00,0x14,0x24,0x83,0x02,0x14,0x20,0x42,0x88,0x02,0x4A,0x10,0x14,0x80,0x00,\
		0x02,0x1C,0x00,0x09,0x83,0x58,0x21,0xAC,0x80,0x00,0xA0,0x13,0x11,0x00,0xA8,0x59
	}};

	ECCPUBLICKEYBLOB pEccPubBlob = {256,{ \
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
		0x26,0xEA,0x8A,0x39,0x30,0x20,0x8E,0xFD,0x91,0x32,0xF7,0x1C,0x51,0x0A,0xAB,0x57, \
		0x43,0x8B,0x3D,0xBC,0x27,0xD3,0x04,0xE7,0x98,0xEC,0xCA,0xF2,0xA0,0xEA,0x74,0xEB \
	}, \
	{ \
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, \
	0x75,0x00,0xD9,0xCF,0xF3,0x0E,0x63,0x10,0x15,0xC7,0x73,0x72,0x8E,0x8C,0x25,0x09, \
	0x38,0x0A,0x22,0xE1,0xE7,0x42,0xB6,0xAB,0xA0,0x9D,0xCF,0x85,0x7C,0x42,0xCC,0xEA \
	}};

	char szContainer[64]={0};
	HCONTAINER hCon;

	memcpy(szContainer,"SM2_Container",13);

	rv = m_PSKF_OpenContainer(hApp,szContainer,&hCon);
	if(rv)
	{
		PrintError("SKF_OpenContainer",rv);
		return rv;
	}

	rv = m_PSKF_ExportPublicKey(hCon,TRUE,(unsigned char *)&pEccSignKey,&ulEccPubKeyLen);
	if(rv)
	{
		PrintError("SKF_ExportPublicKey",rv);
		return rv;
	}


	pEccCipherBlob = (ECCCIPHERBLOB *)malloc(sizeof(ECCCIPHERBLOB)+16-1);
	pEccCipherBlob->CipherLen =16;
	rv = m_PSKF_ECCExportSessionKey (hCon,SGD_SM1_ECB,&pEccSignKey,pEccCipherBlob,&hSessionKey);
	if(rv != SAR_OK)
	{
		PrintError("SKF_ExportPublicKey",rv);
		return rv;
	}

	memcpy(pbTmpData,(char *)&pEccPriBlb.PrivateKey,pEccPriBlb.BitLen/4);
	ulTmpDataLen = pEccPriBlb.BitLen/4;

	EncryptParam.IVLen = 0;
	EncryptParam.PaddingType = 0;
	rv = m_PSKF_EncryptInit(hSessionKey,EncryptParam);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EncryptInit",rv);
		return rv;
	}

	rv = m_PSKF_EncryptUpdate(hSessionKey,pbTmpData,ulTmpDataLen,pbEncryptedData,&ulEncryptedDataLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EncryptUpdate",rv);
		return rv;
	}
	rv = m_PSKF_EncryptFinal(hSessionKey,pbEncryptedData+ulEncryptedDataLen,&rLen);
	if(rv != SAR_OK)
	{
		PrintError("SKF_EncryptFinal",rv);
		return rv;
	}

	ulEncryptedDataLen += rLen;

	pEnvelopedKeyBlob = (PENVELOPEDKEYBLOB)malloc(sizeof(ENVELOPEDKEYBLOB)+16-1);
	if(pEccCipherBlob == NULL)
	{
		LOG_ERROR("申请内存失败!");
		return -1;

	}

	pEnvelopedKeyBlob->Version = 1;
	pEnvelopedKeyBlob->ulSymmAlgID = SGD_SM1_ECB;
	pEnvelopedKeyBlob->ulBits = 256;
	pEnvelopedKeyBlob->PubKey = pEccPubBlob;

	memset(pbEncryptedData,0x00,32);
	memcpy((char *)&(pEnvelopedKeyBlob->ECCCipherBlob),pEccCipherBlob,sizeof(ECCCIPHERBLOB)+16-1);
	memcpy((char *)&(pEnvelopedKeyBlob->cbEncryptedPriKey),&pbEncryptedData,ulEncryptedDataLen);


	rv = m_PSKF_ImportECCKeyPair (hCon,pEnvelopedKeyBlob);
	if(rv != SAR_OK)
	{
		PrintError("SKF_ImportECCKeyPair",rv);
		return rv;
	}
	if(pEnvelopedKeyBlob)
	{
		free(pEnvelopedKeyBlob);
	}
	if(pEccCipherBlob)
	{
		free(pEccCipherBlob);
	}

	LOG_INFO("Import SM2 KeyPiar succeed!\n");

	return SAR_OK;
}


ULONG CReadUKey::ImportSessionKey_Test(DEVHANDLE hDev,HAPPLICATION hApp)
{
	ULONG ulConType = 0,rv =0;
	unsigned char *pbBlob = NULL,*pCipherData = NULL;
	ULONG ulBlobLen = 0;
	HANDLE hSessionKey;

	char szContainer[64]={0};
	HCONTAINER hCon;


	///使用固定的SM2容器  可以枚举枚举容器，获取容器类型
	memcpy(szContainer,"SM2_Container",13);	
	rv = m_PSKF_OpenContainer(hApp,szContainer,&hCon);
	if(rv)
	{
		PrintError("SKF_OpenContainer",rv);
		return rv;
	}

	///因为是SM2，所以预先知道公钥大小，，可以调用两次SKF_ExportPublicKey，第一次获取长度
	pbBlob = (unsigned char *)malloc(sizeof(ECCPUBLICKEYBLOB));
	ulBlobLen = sizeof(ECCPUBLICKEYBLOB);


	/////注意，必须导出加密密钥对的公钥
	rv = m_PSKF_ExportPublicKey(hCon,FALSE,pbBlob,&ulBlobLen);  
	if(rv)
	{	
		LOG_ERROR("SKF_ExportPublicKey failed,rv = 0x%0x",rv);
		if(pbBlob)
		{
			free(pbBlob);
			pbBlob = NULL;
		}
		return rv;		
	}

	ECCCIPHERBLOB *pEccCipher= NULL;
	pEccCipher = (ECCCIPHERBLOB *)malloc(sizeof(ECCCIPHERBLOB)+16-1);
	memset((char *)pEccCipher,0x00,sizeof(ECCCIPHERBLOB)+16-1);

	pEccCipher->CipherLen = 16;   ///必须设定

	rv = m_PSKF_ECCExportSessionKey(hCon,SGD_SM1_ECB,(ECCPUBLICKEYBLOB *)pbBlob,pEccCipher,&hSessionKey);
	if(rv)
	{
		LOG_ERROR("SKF_ECCExportSessionKey failed,rv = 0x%0x",rv);
		if(pbBlob)
		{
			free(pbBlob);
			pbBlob = NULL;
		}
		if(pEccCipher)
		{
			free(pEccCipher);
			pEccCipher = NULL;
		}
		return rv;		
	}

	rv = m_PSKF_ImportSessionKey(hCon,SGD_SM1_ECB,(unsigned char *)pEccCipher,sizeof(ECCCIPHERBLOB)+16-1,&hSessionKey);
	if(rv)
	{
		LOG_ERROR("SKF_ImportSessionKey failed,rv = 0x%0x",rv);
		if(pbBlob)
		{
			free(pbBlob);
			pbBlob = NULL;
		}
		if(pEccCipher)
		{
			free(pEccCipher);
			pEccCipher = NULL;
		}
		return rv;	
	}

	if(pbBlob)
		free(pbBlob);
	if(pEccCipher)
		free(pCipherData);

	LOG_INFO("ImportSessionKey succeed!\n");
	return SAR_OK;


}



void CReadUKey::PrintError(char *szFunName,ULONG dwErrorCode,char *Buf)
{
	LOG_ERROR("the Fun %s failed! the ErrorCode is 0x%0x",szFunName,dwErrorCode);
	if(Buf)
	{
		free(Buf);
		Buf = NULL;

	}
}

ULONG CReadUKey::EnumCertsFromDev(DEVHANDLE hDev,std::vector<ReadCertInfo>& vecCert,char* pDevName)
{
	

	DWORD rv = 0;

	char *szAppList = NULL;
	ULONG ulAppListLen = 0;

	rv= m_PSKF_EnumApplication(hDev,szAppList,&ulAppListLen);
	if(rv)
	{
		PrintError("SKF_EnumApplication",rv);
		return rv;
	}

	if(ulAppListLen < 2)
	{
		LOG_ERROR("No Application!\n");
		return -1;
	}
	szAppList = (char *)malloc(ulAppListLen);
	rv = m_PSKF_EnumApplication(hDev,szAppList,&ulAppListLen);
	if(rv)
	{
		PrintError("SKF_EnumApplication",rv,szAppList);
		return rv;
	}
	printf("Find Application：%s\n",szAppList);

	char *pp = szAppList;
	while(szAppList+ulAppListLen - pp)
	{
		if(strlen(pp))
		{
			HAPPLICATION phApp;
			ULONG rv = m_PSKF_OpenApplication(hDev,pp,&phApp);
			if (rv)
			{
				LOG_INFO("Application name=%s",pp);
				PrintError("SKF_OpenApplication",rv);
				pp+=strlen(pp);
				continue;
			}
			else
			{
				EnumCertsFromApp(hDev,phApp,vecCert,pDevName,pp);
				//m_PSKF_CloseApplication(phApp);
			}

			pp+=strlen(pp);
		}
		else
		{
			pp++;
		}
	}



	
	if(szAppList)
	{
		free(szAppList);
		szAppList = NULL;
	}

	return SAR_OK;
}

ULONG CReadUKey::EnumCertsFromApp(DEVHANDLE hDev,HAPPLICATION phApp,std::vector<ReadCertInfo>& vecCert,char* pDevName,char* pAppName)
{
	char *szConList = NULL;
	ULONG ulConListLen = 0;

	ULONG rv= m_PSKF_EnumContainer(phApp,szConList,&ulConListLen);
	if(rv)
	{
		PrintError("m_PSKF_EnumContainer",rv);
		return rv;
	}

	if(ulConListLen < 2)
	{
		LOG_ERROR("No Container!\n");
		return -1;
	}
	szConList = (char *)malloc(ulConListLen);
	rv = m_PSKF_EnumContainer(phApp,szConList,&ulConListLen);
	if(rv)
	{
		PrintError("m_PSKF_EnumContainer",rv,szConList);
		return rv;
	}
	printf("Find Container：%s\n",szConList);

	char *pp = szConList;
	while(szConList+ulConListLen - pp)
	{
		if(strlen(pp))
		{
			ReadCertInfo tagRCF;
			tagRCF.m_hDev = hDev;
			tagRCF.m_hApp = phApp;
			strcat(tagRCF.m_byPath, pDevName);
			strcat(tagRCF.m_byPath, "||");
			strcat(tagRCF.m_byPath, pAppName);
			//strcat(szCertID, "&&&");
			//tagRCF.m_szDevName = pDevName;
			//tagRCF.m_szAppName = pAppName;
			if(!ExportCert(hDev,pp, phApp, vecCert,pDevName,pAppName))
			{
				//vecCert.push_back(tagRCF);
			}
			pp+=strlen(pp);
		}
		else
		{
			pp++;
		}
	}

	if (szConList)
	{
		free(szConList);
		szConList = NULL;
	}

	return rv;

}

ULONG CReadUKey::GetCertEx(HCONTAINER hContainer, BOOL bSignFlag,  BYTE*& pbCert, ULONG& ulCertLen)
{
	//得到证书
	ULONG rv = m_PSKF_ExportCertificate(hContainer,bSignFlag,pbCert,&ulCertLen);
	if (rv)
	{
		PrintError("m_PSKF_ExportCertificate",rv);
		return rv;
	}

	pbCert = (BYTE *)malloc(ulCertLen);
	rv = m_PSKF_ExportCertificate(hContainer,bSignFlag,pbCert,&ulCertLen);
	if (rv)
	{
		PrintError("m_PSKF_ExportCertificate",rv,(char*)pbCert);
		return rv;
	}

	return rv;
}

ULONG CReadUKey::ExportCert(DEVHANDLE hDev,char* sContainerName,HAPPLICATION phAp,
							std::vector<ReadCertInfo>& vecCert,char* pDevName,char* pAppName)
{
	HCONTAINER phContainer;
	ULONG rv = m_PSKF_OpenContainer(phAp,sContainerName,&phContainer);
	if (rv)
	{
		PrintError("m_PSKF_OpenContainer",rv);
		return rv;
	}

	ReadCertInfo tagRCF;
	tagRCF.m_hDev = hDev;
	tagRCF.m_hApp = phAp;
	strcat(tagRCF.m_byPath, pAppName);
	//tagRCF.m_szContainerName = sContainerName;
	tagRCF.m_hAContainer = phContainer;
	tagRCF.m_bSignFlag = TRUE;
	tagRCF.m_ulCertLen = 0;
	tagRCF.m_pCert = NULL;
	tagRCF.m_pReadUkey = (void*)this;

	strcat(tagRCF.m_byPath, pDevName);
	strcat(tagRCF.m_byPath, "||");
	strcat(tagRCF.m_byPath, pAppName);
	strcat(tagRCF.m_byPath, "||");
	strcat(tagRCF.m_byPath, sContainerName);
//	strcat(tagRCF.m_byPath, "&&&");

	ULONG rvTmp1 = GetCertEx(phContainer,tagRCF.m_bSignFlag,tagRCF.m_pCert,tagRCF.m_ulCertLen);
	if (!rvTmp1)
	{
		vecCert.push_back(tagRCF);
	}

	tagRCF.m_bSignFlag = FALSE;
	tagRCF.m_ulCertLen = 0;
	tagRCF.m_pCert = NULL;
	ULONG rvTmp2 = GetCertEx(phContainer,tagRCF.m_bSignFlag,tagRCF.m_pCert,tagRCF.m_ulCertLen);
	if (!rvTmp2)
	{
		vecCert.push_back(tagRCF);
	}

	if (rvTmp1 && rvTmp2)
	{
		m_PSKF_CloseContainer(phContainer);
		return rvTmp1;
	}

	return rv;

}

ULONG CReadUKey::GetApp(DEVHANDLE hDev,HAPPLICATION *phApp,std::string szAppName)
{
	DWORD rv = 0;

	char *szAppList = NULL;
	ULONG ulAppListLen = 0;

	rv= m_PSKF_EnumApplication(hDev,szAppList,&ulAppListLen);
	if(rv)
	{
		PrintError("SKF_EnumApplication",rv);
		return rv;
	}

	if(ulAppListLen < 2)
	{
		LOG_ERROR("No Application!\n");
		return -1;
	}
	szAppList = (char *)malloc(ulAppListLen);
	rv = m_PSKF_EnumApplication(hDev,szAppList,&ulAppListLen);
	if(rv)
	{
		PrintError("SKF_EnumApplication",rv,szAppList);
		return rv;
	}
	printf("Find Application：%s\n",szAppList);

	rv = m_PSKF_OpenApplication(hDev,szAppList,phApp);
	if (rv)
	{
		PrintError("SKF_OpenApplication",rv,szAppList);
		return rv;
	}


	LOG_INFO("SKF_OpenApplication %s succeed!\n",szAppList);
	if(szAppList)
	{
		free(szAppList);
		szAppList = NULL;
	}

	return SAR_OK;
}

ULONG CReadUKey::CheckPin(DEVHANDLE hDev,HAPPLICATION hApp,std::string szPin)
{

	ULONG rv = SAR_OK,ulRetryCount =0;

	rv = m_PSKF_VerifyPIN(hApp,USER_TYPE,(LPSTR)szPin.c_str(),&ulRetryCount);
	if(rv)
	{
		PrintError("SKF_VerifyPIN",rv);
		return rv;
	}

	return rv;

}

ULONG CReadUKey::DigestEx(std::string szGenRandom,DEVHANDLE hDev,BYTE*& pbHashData,ULONG* pulHashLen,int nType)
{
	ULONG ulDataLen = szGenRandom.length();
	BYTE* pbData = (BYTE*)malloc(ulDataLen+1);
	memset(pbData,0,ulDataLen+1);
	memcpy(pbData,szGenRandom.c_str(),ulDataLen);

	unsigned char pbDigest[32]={0};
	ULONG ulDigestLen = 32;


	HANDLE hHash;
	ECCPUBLICKEYBLOB PubKey;
	unsigned char pucID[0x20]={0};

	ULONG rv = m_PSKF_DigestInit(hDev,nType,&PubKey,pucID,16,&hHash);
	if(rv)
	{
		free((char*)pbData);
		PrintError("SKF_DigestInit",rv);
		return rv;
	}


	rv = m_PSKF_Digest(hHash,pbData,ulDataLen,pbHashData,pulHashLen);
	if(rv)
	{
		free((char*)pbData);
		PrintError("SKF_Digest",rv);
		return rv;
	}


	pbHashData = (BYTE*)malloc(*pulHashLen+1);
	memset(pbHashData,0,*pulHashLen+1);
	rv = m_PSKF_Digest(hHash,pbData,ulDataLen,pbHashData,pulHashLen);
	if(rv)
	{
		free((char*)pbData);
		PrintError("SKF_Digest",rv);
		return rv;
	}

	CString strInfo,sMsg;

	for (int i = 0; i<20;i++)
	{
		sMsg.Format("%x",pbHashData[i]);
		strInfo += sMsg;
	}

	LOG_INFO(strInfo);

	free((char*)pbData);
	return rv;
}

ULONG CReadUKey::DigestEx2(std::string szGenRandom,DEVHANDLE hDev,BYTE*& pbHashData,ULONG* pulHashLen,int nType)
{
	ULONG ulDataLen = szGenRandom.length();
	BYTE* pbData = (BYTE*)malloc(ulDataLen+1);
	memset(pbData,0,ulDataLen+1);
	memcpy(pbData,szGenRandom.c_str(),ulDataLen);

	unsigned char pbDigest[32]={0};
	ULONG ulDigestLen = 32;


	HANDLE hHash;
	ECCPUBLICKEYBLOB PubKey;
	unsigned char pucID[0x20]={0};

	ULONG rv = m_PSKF_DigestInit(hDev,nType,&PubKey,pucID,16,&hHash);
	if(rv)
	{
		free((char*)pbData);
		PrintError("SKF_DigestInit",rv);
		return rv;
	}

	rv = m_PSKF_DigestUpdate(hHash, pbData, ulDataLen);
	if(rv)
	{
		free((char*)pbData);
		PrintError("SKF_DigestFinal",rv);
		return rv;
	}

	pbHashData = (BYTE*)malloc(400);
	memset(pbHashData,0,400);
	*pulHashLen = 400;

	rv = m_PSKF_DigestFinal(hHash, pbHashData, pulHashLen);
	if(rv)
	{
		free((char*)pbData);
		PrintError("SKF_DigestFinal",rv);
		return rv;
	}

	free((char*)pbData);
	return rv;
}

ULONG CReadUKey::RSASignDataEx2(HCONTAINER hCon,BYTE* pData,ULONG ulDataLen,BYTE*& pbSignature,ULONG* pulSignLen)
{
//	ULONG ulDataLen = strlen((char*)pData);

	ULONG rv = m_PSKF_RSASignData(hCon,pData,ulDataLen,pbSignature,pulSignLen);
	if (rv)
	{
		PrintError("m_PSKF_RSASignData",rv);
		return rv;
	}



	pbSignature = (BYTE*)malloc(*pulSignLen+1);
	memset(pbSignature,0,*pulSignLen+1);
	rv = m_PSKF_RSASignData(hCon,pData,ulDataLen,pbSignature,pulSignLen);
	if (rv)
	{
		PrintError("m_PSKF_RSASignData",rv);
		return rv;
	}
	else
	{
		LOG_INFO("m_PSKF_RSASignData pbData=%s,pbSignature=%s",(char*)pData,(char*)pbSignature);
	}



	return rv;
}


ULONG CReadUKey::RSASignDataEx(HCONTAINER hCon,std::string szGenRandom,BYTE*& pbSignature,ULONG* pulSignLen)
{
	ULONG ulDataLen = szGenRandom.length();
	BYTE* pData = (BYTE*)malloc(ulDataLen+1);
	memset(pData,0,ulDataLen+1);
	memcpy(pData,szGenRandom.c_str(),ulDataLen);

	ULONG rv = m_PSKF_RSASignData(hCon,pData,ulDataLen,pbSignature,pulSignLen);
	if (rv)
	{
		free(pData);
		PrintError("m_PSKF_RSASignData",rv);
		return rv;
	}

	

	pbSignature = (BYTE*)malloc(*pulSignLen+1);
	memset(pbSignature,0,*pulSignLen+1);
	rv = m_PSKF_RSASignData(hCon,pData,ulDataLen,pbSignature,pulSignLen);
	if (rv)
	{
		free(pData);
		PrintError("m_PSKF_RSASignData",rv);
		return rv;
	}
	else
	{
		LOG_INFO("m_PSKF_RSASignData pbData=%s,pbSignature=%s",(char*)pData,(char*)pbSignature);
	}

	free((char*)pData);


	return rv;
}

ULONG CReadUKey::ECCSignDataEx(HCONTAINER hCon,std::string szGenRandom,BYTE*& pbSignature,ULONG* pulSignLen)
{
	ULONG ulDataLen = szGenRandom.length();
	BYTE* pData = (BYTE*)malloc(ulDataLen+1);
	memset(pData,0,ulDataLen+1);
	memcpy(pData,szGenRandom.c_str(),ulDataLen);

	

	ECCSIGNATUREBLOB signdata;

	ULONG rv = m_PSKF_ECCSignData(hCon,pData,ulDataLen,&signdata);
	if (rv)
	{
		free(pData);
		PrintError("m_PSKF_ECCSignData",rv);
		return rv;
	}


	free(pData);

	pbSignature = (BYTE*)malloc(65);
	memset(pbSignature,0,65);
	memcpy(pbSignature,signdata.r+32,32);
	memcpy(pbSignature+32,signdata.s+32,32);

	*pulSignLen = 64;

	LOG_INFO("ECCSignDataEx pbData=%s,pbSignature=%s",szGenRandom.c_str(), pbSignature);


	return rv;
}

ULONG CReadUKey::ECCSignDataEx2(HCONTAINER hCon,BYTE* pData,ULONG ulDataLen,BYTE*& pbSignature,ULONG* pulSignLen)
{

	ECCSIGNATUREBLOB signdata;

	ULONG rv = m_PSKF_ECCSignData(hCon,pData,ulDataLen,&signdata);
	if (rv)
	{
		PrintError("m_PSKF_ECCSignData",rv);
		return rv;
	}

	int nlen = sizeof(ECCSIGNATUREBLOB);

	if (0)//根据demo是整体值
	{
		pbSignature = (BYTE*)malloc(nlen+1);
		memset(pbSignature,0,nlen+1);
		memcpy(pbSignature,&signdata,nlen);
		*pulSignLen = nlen;

	}
	else
	{
		pbSignature = (BYTE*)malloc(65);
		memset(pbSignature,0,65);
		memcpy(pbSignature,signdata.r+32,32);
		memcpy(pbSignature+32,signdata.s+32,32);

		*pulSignLen = 64;
	}
	

	LOG_INFO("ECCSignDataEx2 pbData=%s,pbSignature=%s",(char*)pData, pbSignature);


	return rv;
}

ULONG CReadUKey::RSAPriKeyDecryptEx(HCONTAINER hContainer, std::string szInData, OUT BYTE*& pbOutData, IN OUT DWORD *pdwOutDataLen)
{

	ULONG ulDataLen = szInData.length();
	BYTE* pData = (BYTE*)malloc(ulDataLen+1);
	memset(pData,0,ulDataLen+1);
	memcpy(pData,szInData.c_str(),ulDataLen);

	ULONG rv = m_PSKF_RSAPriKeyDecrypt(hContainer,pData,ulDataLen,pbOutData,pdwOutDataLen);
	if (rv)
	{
		free(pData);
		PrintError("m_PSKF_RSAPriKeyDecrypt",rv);
		return rv;
	}



	pbOutData = (BYTE*)malloc(*pdwOutDataLen+1);
	memset(pbOutData,0,*pdwOutDataLen+1);
	rv = m_PSKF_RSAPriKeyDecrypt(hContainer,pData,ulDataLen,pbOutData,pdwOutDataLen);
	if (rv)
	{
		free(pData);
		PrintError("m_PSKF_RSAPriKeyDecrypt",rv);
		return rv;
	}
	else
	{
		LOG_INFO("m_PSKF_RSAPriKeyDecrypt pbData=%s,pbOutData=%s",(char*)pData,(char*)pbOutData);
	}

	free((char*)pData);


	return rv;
}

ULONG CReadUKey::RSAPriKeyDecryptEx2(HCONTAINER hContainer, IN BYTE *pbInData, IN DWORD dwInDataLen, OUT BYTE*& pbOutData, IN OUT DWORD *pdwOutDataLen)
{
	ULONG rv = m_PSKF_RSAPriKeyDecrypt(hContainer,pbInData,dwInDataLen,pbOutData,pdwOutDataLen);
	if (rv)
	{
		PrintError("m_PSKF_RSAPriKeyDecrypt",rv);
		return rv;
	}



	pbOutData = (BYTE*)malloc(*pdwOutDataLen+1);
	memset(pbOutData,0,*pdwOutDataLen+1);
	rv = m_PSKF_RSAPriKeyDecrypt(hContainer,pbInData,dwInDataLen,pbOutData,pdwOutDataLen);
	if (rv)
	{
		PrintError("m_PSKF_RSAPriKeyDecrypt",rv);
		return rv;
	}
	else
	{
		LOG_INFO("m_PSKF_RSAPriKeyDecrypt pbData=%s,pbOutData=%s",(char*)pbInData,(char*)pbOutData);
	}


	return rv;
}

ULONG CReadUKey::RSAPubKeyEncryptEx(DEVHANDLE hDev, IN RSAPUBLICKEYBLOB *pRSAPubKeyBlob,std::string szInData, 
						 OUT BYTE*& pbOutData, IN OUT DWORD *pdwOutDataLen)
{
	ULONG ulDataLen = szInData.length();
	BYTE* pData = (BYTE*)malloc(ulDataLen+1);
	memset(pData,0,ulDataLen+1);
	memcpy(pData,szInData.c_str(),ulDataLen);

	ULONG rv = m_PSKF_RSAPubKeyEncrypt(hDev,pRSAPubKeyBlob,pData,ulDataLen,pbOutData,pdwOutDataLen);
	if (rv)
	{
		free(pData);
		PrintError("m_PSKF_RSAPubKeyEncrypt",rv);
		return rv;
	}



	pbOutData = (BYTE*)malloc(*pdwOutDataLen+1);
	memset(pbOutData,0,*pdwOutDataLen+1);
	rv = m_PSKF_RSAPubKeyEncrypt(hDev,pRSAPubKeyBlob,pData,ulDataLen,pbOutData,pdwOutDataLen);
	if (rv)
	{
		free(pData);
		PrintError("m_PSKF_RSAPubKeyEncrypt",rv);
		return rv;
	}
	else
	{
		LOG_INFO("m_PSKF_RSAPubKeyEncrypt pbData=%s,pbOutData=%s",(char*)pData,(char*)pbOutData);
	}

	free((char*)pData);


	return rv;
}

ULONG CReadUKey::ECCDecryptEx2(IN HCONTAINER hContainer, IN PECCCIPHERBLOB pCipherText, 
							   OUT BYTE*& pbOutData, IN OUT ULONG *pdwOutDataLen)
{
	

	ULONG rv = m_PSKF_ECCDecrypt(hContainer,pCipherText,pbOutData,pdwOutDataLen);
	if (rv)
	{
		PrintError("m_PSKF_ECCDecrypt",rv);
		return rv;
	}



	pbOutData = (BYTE*)malloc(*pdwOutDataLen+1);
	memset(pbOutData,0,*pdwOutDataLen+1);
	rv =m_PSKF_ECCDecrypt(hContainer,pCipherText,pbOutData,pdwOutDataLen);
	if (rv)
	{
		PrintError("m_PSKF_ECCDecrypt",rv);
		return rv;
	}
	else
	{
		std::string szInfo((char*)pbOutData,*pdwOutDataLen);
		LOG_INFO("m_PSKF_ECCDecrypt pbOutData=%s",szInfo.c_str());
	}


	return rv;
}