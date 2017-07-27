// PinDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "CAPCManage.h"
#include "PinDlg.h"
#include "ReadUKey.h"

extern CReadUKey* g_readUKey;
// CPinDlg 对话框

IMPLEMENT_DYNAMIC(CPinDlg, CDialog)

CPinDlg::CPinDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CPinDlg::IDD, pParent)
{

}

CPinDlg::~CPinDlg()
{
}

void CPinDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CPinDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CPinDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CPinDlg 消息处理程序

void CPinDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	CString strPin;
	GetDlgItemText(IDC_PIN_EDIT,strPin);
	if (strPin.IsEmpty())
	{
		return;
	}

	int rv = -1;

	//int rv = g_readUKey->GetApp(g_readUKey->m_hDev,&(g_readUKey->m_hApp),"EnterSafe");
	//if (rv)
	//{
	//	return;
	//}

	rv = g_readUKey->CheckPin(g_readUKey->m_hDev,g_readUKey->m_hApp,strPin.GetBuffer());
	if (rv)
	{
		AfxMessageBox("PIN 码 错误，请重新输入！");
		return;
	}
	

	OnOK();
}
