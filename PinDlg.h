#pragma once


// CPinDlg 对话框

class CPinDlg : public CDialog
{
	DECLARE_DYNAMIC(CPinDlg)

public:
	CPinDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CPinDlg();

// 对话框数据
	enum { IDD = IDD_PIN_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
};
