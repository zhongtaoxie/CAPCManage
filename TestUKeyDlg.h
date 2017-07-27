#pragma once

#include "ReadUKey.h"
// CTestUKeyDlg 对话框

class CTestUKeyDlg : public CDialog
{
	DECLARE_DYNAMIC(CTestUKeyDlg)

public:
	CTestUKeyDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CTestUKeyDlg();

// 对话框数据
	enum { IDD = IDD_TESTUKEY_DIALOG };

public:

	int Test2();

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnGetdevinfo();
	virtual BOOL OnInitDialog();
	afx_msg void OnBnClickedBtnAppManage();
};
