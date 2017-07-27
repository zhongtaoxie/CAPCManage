#include "StdAfx.h"
#include "HttpProtocol2.h"
#include "httpserver/HttpProtocol.h"
#include "CAPCManage.h"
#include "ParserPostMsg.h"
#include "CAPCManageDlg.h"
#include "EnDecodeClass.h"



/// 宏定义
#define DATA_BUFSIZE 65536


/// 全局函数定义
CString g_szRevData;
extern CCAPCManageDlg* g_pCADlg;

// 格林威治时间的星期转换
extern char *week[];

// 格林威治时间的月份转换
extern char *month[];



///////////////////////////////////////////////////////////////////////
//
// 函数名       : InitWinsock
// 功能描述     : 初始化WINSOCK
// 返回值       : void
//
///////////////////////////////////////////////////////////////////////
void InitWinsock()
{
	// 初始化WINSOCK
	WSADATA wsd;
	if( WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
		return ;

}

///////////////////////////////////////////////////////////////////////
//
// 函数名       : BindServerOverlapped
// 功能描述     : 绑定端口，并返回一个 Overlapped 的Listen Socket
// 参数         : int nPort
// 返回值       : SOCKET
//
///////////////////////////////////////////////////////////////////////
SOCKET BindServerOverlapped(int nPort)
{
	// 创建socket
	SOCKET sServer = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);

	// 绑定端口
	struct sockaddr_in servAddr;
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(nPort);
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if(bind(sServer, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
	{
		LOG_ERROR("bind Failed!");
		return NULL;
	}

	// 设置监听队列为200
	if(listen(sServer, 200) != 0)
	{
		LOG_ERROR("listen Failed!");
		return NULL;
	}
	return sServer;
}


/// 结构体定义
typedef struct
{
	OVERLAPPED Overlapped;
	WSABUF DataBuf;
	CHAR Buffer[DATA_BUFSIZE];
} PER_IO_OPERATION_DATA, * LPPER_IO_OPERATION_DATA;


typedef struct
{
	SOCKET Socket;
} PER_HANDLE_DATA, * LPPER_HANDLE_DATA;


void CHttpProtocol2::SendLoginResp(PREQUEST pReq,std::string szResp)
{

	char msg[12048] = " ";
	char curTime[50] = " ";
	GetCurentTime((char*)curTime);

	// 取得文件的last-modified时间
	char last_modified[60] = " ";
	GetLastModified(pReq->hFile, (char*)last_modified);	
	// 取得文件的类型
	char ContenType[50] = " ";
	GetContenType(pReq, (char*)ContenType);
	//szResp="{\"resultCode\":1,\"resultMsg\":\"CA认证失败！\"}";

	CEnDecodeClass::Gbk2Utf(szResp);
	DWORD length = szResp.length();


	sprintf((char*)msg, "HTTP/1.1 200 OK\r\n%s\r\n%s\r\nContent-Type: %s\r\nContent-Length: %d\r\n%s\r\n\r\n%s\r\n",
		"Server: Apache-Coyote/1.1",				// Date
		"Access-Control-Allow-Origin: *",       // Server
		"application/json;charset=UTF-8",				// Content-Type
		length,					// Content-length
		curTime,
		szResp.c_str());			// Last-Modified

	// 返回响应

	int sdf = strlen(msg);

	send(pReq->Socket, msg, strlen(msg), 0);	

	LOG_INFO(szResp.c_str());
}

DWORD WINAPI ProcessIO(LPVOID lpParam)
{
	HANDLE CompletionPort = (HANDLE)lpParam;
	DWORD BytesTransferred;
	LPPER_HANDLE_DATA PerHandleData;
	LPPER_IO_OPERATION_DATA PerIoData;

	while(true)
	{

		if(0 == GetQueuedCompletionStatus(CompletionPort, &BytesTransferred, (LPDWORD)&PerHandleData, (LPOVERLAPPED*)&PerIoData, INFINITE))
		{
			if( (GetLastError() == WAIT_TIMEOUT) || (GetLastError() == ERROR_NETNAME_DELETED) )
			{
//				cout << "closing socket" << PerHandleData->Socket << endl;

				closesocket(PerHandleData->Socket);

				delete PerIoData;
				delete PerHandleData;
				continue;
			}
			else
			{
				LOG_ERROR("GetQueuedCompletionStatus failed!");
			}
			return 0;
		}

		// 说明客户端已经退出
		if(BytesTransferred == 0)
		{
		//	cout << "closing socket" << PerHandleData->Socket << endl;
			closesocket(PerHandleData->Socket);
			delete PerIoData;
			delete PerHandleData;
			continue;
		}


		// 取得数据并处理
	//	cout << PerHandleData->Socket << "发送过来的消息：" << PerIoData->Buffer << endl;
		CString strData = CString(PerIoData->Buffer,BytesTransferred);
		if (0 == strData.Find("POST /caclient"))
		{
			g_szRevData = strData;
		}
		else
		{
			g_szRevData += strData;
		}

		if (DATA_BUFSIZE != BytesTransferred)
		{
			int nRet =  g_pCADlg->m_parsermsg.JustMsgFormat(g_szRevData);
			if (0 == nRet)
			{
				PREQUEST pReq = new REQUEST;
				pReq->pHttpProtocol = g_pCADlg->m_pHttpProtocol;
				pReq->Socket = PerHandleData->Socket;

				// 分析request信息
				g_pCADlg->m_parsermsg.Analyze(pReq,(LPBYTE)g_szRevData.GetBuffer());
				g_szRevData.Empty();
			}
			else if (-2 == nRet)
			{
				g_szRevData.Empty();
			}
		}

		

		// 继续向 socket 投递WSARecv操作
		DWORD Flags = 0;
		DWORD dwRecv = 0;
		ZeroMemory(PerIoData, sizeof(PER_IO_OPERATION_DATA));
		PerIoData->DataBuf.buf = PerIoData->Buffer;
		PerIoData->DataBuf.len = DATA_BUFSIZE;
		WSARecv(PerHandleData->Socket, &PerIoData->DataBuf, 1, &dwRecv, &Flags, &PerIoData->Overlapped, NULL); 
	}

	return 0;
}



bool CHttpProtocol2::StartHttpSrv()
{
	InitWinsock();

	m_CompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

	// 根据系统的CPU来创建工作者线程
	SYSTEM_INFO SystemInfo;
	GetSystemInfo(&SystemInfo);

	//for(int i = 0; i < SystemInfo.dwNumberOfProcessors * 2; i++)
	//{
	//	// if(hProcessIO)
	//}

	HANDLE hProcessIO = CreateThread(NULL, 0, ProcessIO, m_CompletionPort, 0, NULL);

	// 创建侦听SOCKET
	m_listenSocket = BindServerOverlapped(m_nPort);

	CWinThread* m_pListenThread = AfxBeginThread(ListenThread, this);
	if (!m_pListenThread)
	{
		// 线程创建失败
		LOG_ERROR("Could not create listening thread" );
		closesocket(m_listenSocket);	// 断开链接
		return false;
	}


	return true;
}

UINT CHttpProtocol2::ListenThread(LPVOID param)
{
	CHttpProtocol2* pHttpPor2 = (CHttpProtocol2*)param;
	SOCKET sClient;
	LPPER_HANDLE_DATA PerHandleData;
	LPPER_IO_OPERATION_DATA PerIoData;
	while(true)
	{
		// 等待客户端接入
		//sClient = WSAAccept(sListen, NULL, NULL, NULL, 0);
		sClient = accept(pHttpPor2->m_listenSocket, 0, 0);
		//发送缓冲区
		int nSendBuf=1024;//设置为32K
		//setsockopt(sClient,SOL_SOCKET,SO_SNDBUF,(const char*)&nSendBuf,sizeof(int));

		//cout << "Socket " << sClient << "连接进来" << endl;

		PerHandleData = new PER_HANDLE_DATA();
		PerHandleData->Socket = sClient;

		// 将接入的客户端和完成端口联系起来
		CreateIoCompletionPort((HANDLE)sClient, pHttpPor2->m_CompletionPort, (DWORD)PerHandleData, 0);

		// 建立一个Overlapped，并使用这个Overlapped结构对socket投递操作
		PerIoData = new PER_IO_OPERATION_DATA();

		ZeroMemory(PerIoData, sizeof(PER_IO_OPERATION_DATA));
		PerIoData->DataBuf.buf = PerIoData->Buffer;
		PerIoData->DataBuf.len = DATA_BUFSIZE;

		// 投递一个WSARecv操作
		DWORD Flags = 0;
		DWORD dwRecv = 0;
		WSARecv(sClient, &PerIoData->DataBuf, 1, &dwRecv, &Flags, &PerIoData->Overlapped, NULL);
	}

	DWORD dwByteTrans;
	PostQueuedCompletionStatus(pHttpPor2->m_CompletionPort, dwByteTrans, 0, 0);
	closesocket(pHttpPor2->m_listenSocket);
}

CHttpProtocol2::CHttpProtocol2(void)
{
}

CHttpProtocol2::~CHttpProtocol2(void)
{
}

// 活动本地时间
void CHttpProtocol2::GetCurentTime(LPSTR lpszString)
{  
	// 活动本地时间
	SYSTEMTIME st;
	GetLocalTime(&st);
	// 时间格式化
	wsprintf(lpszString, "%s %02d %s %d %02d:%02d:%02d GMT",week[st.wDayOfWeek], st.wDay,month[st.wMonth-1],
		st.wYear, st.wHour, st.wMinute, st.wSecond);
}

bool CHttpProtocol2::GetLastModified(HANDLE hFile, LPSTR lpszString)
{
	// 获得文件的last-modified 时间
	FILETIME ftCreate, ftAccess, ftWrite;
	SYSTEMTIME stCreate;
	FILETIME ftime;	
	// 获得文件的last-modified的UTC时间
	if (!GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))   
		return false;
	FileTimeToLocalFileTime(&ftWrite,&ftime);
	// UTC时间转化成本地时间
	FileTimeToSystemTime(&ftime, &stCreate);	
	// 时间格式化
	wsprintf(lpszString, "%s %02d %s %d %02d:%02d:%02d GMT", week[stCreate.wDayOfWeek],
		stCreate.wDay, month[stCreate.wMonth-1], stCreate.wYear, stCreate.wHour,
		stCreate.wMinute, stCreate.wSecond);
	return TRUE;
}

bool CHttpProtocol2::GetContenType(PREQUEST pReq, LPSTR type)
{   
	wsprintf(type,"%s","wwwserver/isapi");
	return TRUE;

	//// 取得文件的类型
	//CString cpToken;
	//cpToken = strstr(pReq->szFileName, ".");
	//strcpy(pReq->postfix, cpToken);
	//// 遍历搜索该文件类型对应的content-type
	//map<CString, char *>::iterator it = m_typeMap.find(pReq->postfix);
	//if(it != m_typeMap.end()) 	
	//{
	//	wsprintf(type,"%s",(*it).second);
	//}
	//return TRUE;
}

void CHttpProtocol2::StopHttpSrv()
{


	LOG_INFO("Server Stopped");

}