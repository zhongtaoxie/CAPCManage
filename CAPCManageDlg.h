
// CAPCManageDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "define.h"
#include "SysConfigInfo.h"
#include "httpserver/HttpProtocol.h"
#include "ReadUKey.h"

#include "ParserPostMsg.h"
#include "HttpProtocol2.h"
// CCAPCManageDlg 对话框
class CCAPCManageDlg : public CDialog
{
// 构造
public:
	CCAPCManageDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_CAPCMANAGE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

public:
	std::vector<ReadCertInfo> m_vecCert;//证书的相关信息

	CParserPostMsg m_parsermsg;
	CHttpProtocol2 *m_pHttpProtocol;

private:
	std::string m_szRandom;
	
	std::vector<RegWinInfo>  m_vecRWI; //regWin.xml信息
	std::vector<DevNameDll> m_vecDev; //已经导入的硬件设备名称Dll路径
	CDiscInfo m_diskInfo;
	int m_nSelect;

	

	DWORD m_dwReceived;
	DWORD m_dwTransferred;

	BOOL m_bStart;

	PREQUEST m_pReq;
	int m_nMode;

	

public:
	void GetExePath();
	BOOL GetGenRandomFromServer(std::string& szResp);
	BOOL initList();
	void CollectUSBInfo();
	void ImportUKeyDlls();

	RegWinInfo* GetDevName(std::string szPID,std::string szVID);
	BOOL IsDevExist(std::string szDevName);
	std::string GetDLlFromName(RegWinInfo* pTagRWI);
	void ClearData();
	void SetContainerCloseStatus(HCONTAINER  hAContainer);
	void SetAppCloseStatus(HCONTAINER  hApp);

	BOOL StartServer();

	BOOL SendLoginResp(std::string szResp);
	BOOL analysisCert();
	BOOL analysisSM2Cert();
	BOOL analysisCert2(unsigned char* p,int len,int& nRow, CReadUKey* pReadUKey);
	BOOL analysisCert3(unsigned char* p,int len,int& nRow, CReadUKey* pReadUKey);
	void SaveBase64(char* szbuf, CString strFileName);


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();

	afx_msg LRESULT AddLog(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT ShowData(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnLogin(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedBtnLogin();
	CListCtrl m_listCert;
	afx_msg void OnBnClickedBtnRequest();
protected:
	virtual LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam);
	virtual BOOL OnWndMsg(UINT message, WPARAM wParam, LPARAM lParam, LRESULT* pResult);
public:
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnDestroy();
	afx_msg void OnNcPaint();
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnClose();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnClickedOk();
	afx_msg void OnNMDblclkList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButton3();
};
