#pragma once


// CTestCADlg2 对话框

class CTestCADlg2 : public CDialog
{
	DECLARE_DYNAMIC(CTestCADlg2)

public:
	CTestCADlg2(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CTestCADlg2();

// 对话框数据
	enum { IDD = IDD_TESTCA_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnGenrandom();
	afx_msg void OnBnClickedBtnGetinstance();
	afx_msg void OnBnClickedBtnVerifySignedData();
	afx_msg void OnBnClickedBtnQueryCerttrustlist();
	afx_msg void OnBnClickedBtnVerifySigneddatabyp7();
	afx_msg void OnBnClickedBtnSetCerttrustlist();
	afx_msg void OnBnClickedBtnGetP7signdatainfo();
	afx_msg void OnBnClickedBtnVerifyTimestamp();
	afx_msg void OnBnClickedBtnPubkeyEncrypt();
	afx_msg void OnBnClickedBtnVerifysignedfile();
	afx_msg void OnBnClickedBtnGetServercertificate();
	afx_msg void OnBnClickedBtnGetCertinfobyoid();
	afx_msg void OnBnClickedBtnDelCerttrustlist();
	afx_msg void OnBnClickedBtnGetXmlsignatureinfo();
	afx_msg void OnBnClickedBtnVerifySigneddataxml();
	afx_msg void OnBnClickedBtnSignData();
	afx_msg void OnBnClickedBtnSignFile();
	afx_msg void OnBnClickedBtnPrikeyDecrypt();
	afx_msg void OnBnClickedBtnSetWebappname();
	afx_msg void OnBnClickedBtnGetSignmethod();
	afx_msg void OnBnClickedBtnSetEncryptmethod();
	afx_msg void OnBnClickedBtnCreateTimestamprequest();
	afx_msg void OnBnClickedBtnGetEncryptmethod();
	afx_msg void OnBnClickedBtnCreateTimestampresponse();
	afx_msg void OnBnClickedBtnValidateCert();
	afx_msg void OnBnClickedBtnDecryptFile();
	afx_msg void OnBnClickedBtnSetSignmethod();
	afx_msg void OnBnClickedBtnGetTimestampinfo();
	afx_msg void OnBnClickedBtnSignDatabyp7();
	afx_msg void OnBnClickedBtnEncryptFile();
	afx_msg void OnBnClickedBtnSignDataxml();
	afx_msg void OnBnClickedBtnDecryptData();
	afx_msg void OnBnClickedBtnQueryCerttrustlistaltnames();
	afx_msg void OnBnClickedBtnGetCertinfo();
	afx_msg void OnBnClickedBtnEncryptData();
};
