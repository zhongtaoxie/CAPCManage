#pragma once

#include "httpserver/HttpProtocol.h"
class CHttpProtocol2
{
public:
	CHttpProtocol2(void);
	~CHttpProtocol2(void);


	bool StartHttpSrv();
	void SendLoginResp(PREQUEST pReq, std::string szResp);
	static UINT ListenThread(LPVOID param);

	void GetCurentTime(LPSTR lpszString);
	bool GetLastModified(HANDLE hFile, LPSTR lpszString);
	bool GetContenType(PREQUEST pReq, LPSTR type);
	void StopHttpSrv();



	SOCKET m_listenSocket;
	HANDLE m_CompletionPort;
	HWND m_hwndDlg;
	UINT	m_nPort;					// http server的端口号
	CString m_strRootDir;				// web的根目录
};
