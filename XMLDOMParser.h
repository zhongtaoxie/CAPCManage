/******************************************************************************

                  版权所有 (C), 2007-2050, 华为技术有限公司
******************************************************************************
   文 件 名   : XMLDOMParser.h
   版 本 号   : 1.0
   作    者   : xzt
   生成日期   : 2007-10-10
   最近修改   :
   功能描述   : 为了更方便的读写XML文档,对MSXML4.0类进行封装
				主要解决一些接口参数转换问题
				使用前确保已经安装好MSXML4.0且设置好环境
   函数列表   :
   修改历史   :

******************************************************************************/

#ifndef	_CXMLDOMPARSER_H
#define	_CXMLDOMPARSER_H

#include <atlbase.h>
#include <string>
#include <msxml2.h>
#include "define.h"
using namespace std;

class CXMLDOMParser
{
public:
	CXMLDOMParser()
	{
		CoInitialize(NULL);
		m_pIXMLDoc = NULL;
		m_bSave = false;
	}
	~CXMLDOMParser()
	{
		SafeReleaseXMLDoc();
		CoUninitialize();
	}

	// 创建一个XML文档,成功返回true,失败返回false
	bool	ConstructXMLFile();

	// 从文件加载一个XML文件,加载成功返回true,加载失败返回false
	bool	LoadFromXMLFile(const std::string& fileName);

	// 保存XML文件到fileName,成功返回true,失败返回false
	bool	SaveToXMLFile(const std::string& fileName);

	// 安全释放XML文档
	void	SafeReleaseXMLDoc();

	// 获得XML文件内容

	// 在文档pIParentElem元素下添加nodeName节点,值为nodeValue
	bool	AppendMemberNode(	const std::string& nodeName,
								const std::string& nodeValue,
								IXMLDOMElement*    pIParentElem,
								IXMLDOMNode**	   ppOutNewChild=NULL);

	// 在文档pIParentElem元素下添加nodeName节点,值为nodeValue
    bool   AppendMemberNodeNoValue(const std::string& nodeName,
							  const std::string& nodeValue,
							  IXMLDOMElement*    pIParentElem,
							  IXMLDOMNode**		 ppOutNewChild);

	// 为元素pIParentElem添加属性
	bool	AppendAttributeNode(const std::string&	nodeName,
								const std::string&	nodeValue,
								IXMLDOMElement*		pIParentElem);



	// 获取pIParentElem元素下nodeName节点的值

	// 获得节点pIParentElem的属性
	bool	GetAttributeNode(IXMLDOMNode*		pIParentElem,
							 const std::string&	nodeName,
							 std::string&		nodeValue);
     
	//设置节点的属性值
	bool	SetAttributeNode(IXMLDOMNode*		pIParentElem,
							 const std::string&	nodeName,
							 const std::string&		nodeValue);

	// 获得文档元素
	IXMLDOMElement*	GetDocElem();
	
	// 获得节点的nodeName孩子
	IXMLDOMNode*	GetChildNode(IXMLDOMNode*		pIParentElem,
								 const std::string& nodeName,
								 std::string&		nodeValue);


	bool LoadFromXMLFile(CString& fileName,CString& XSDFileName);
	int CheckXmlLoad(IXMLDOMDocument2 *pDoc);
	//获得XML文件的名称；
	CString GetFileName()  
	{
		return m_fileName;
	}
	void SetFileName(CString FileName)
	{
		m_fileName = FileName;
	}

	void SetFileSave(bool bSave)
	{ 
		m_bSave =  bSave;
	}
	bool GetFileSave()
	{
		return m_bSave;
	}
	
	/////////////////////////////新添加--xzt
	IXMLDOMNode* getChildByName(IXMLDOMNode* pIParentElem,CString nodeName, bool bRecursive = false);
	
	//通过节点的属性得到节点的值
	bool CXMLDOMParser::GetValueByNodeAttribute(IXMLDOMNode* pIParentElem,
											CString strAttributeName, 
											CString strAttributeValue,
											CString& strNodeValue);

	//通过节点的属性得到节点的值
	IXMLDOMNode* CXMLDOMParser::GetChildByNodeAttribute(IXMLDOMNode* pIParentElem, 
													CString strAttributeName, 
													CString strAttributeValue);

	//检查sAW在AW定义文件中否存在，如果存在返回节点的指针
	IXMLDOMNode* CheckAW(IXMLDOMNode* pIParentElem, CString sAW);

	//检查ssParam参数在pIParentElem中否存在，如果存在返回节点的指针
	bool CheckParam(IXMLDOMNode* pIParentElem, CString sParam);

	CString GetAWOrLogicValue(IXMLDOMNode*	pINode);

	CString GetParaValue(IXMLDOMNode*	pINode);

	//获取节点的文本值
	static CString GetNodeText(IXMLDOMNode* pNode);

	// 获得元素属性的值
	static bool GetAttributeValue(IXMLDOMNode*			pIParentElem,
							      const std::string&	nodeName,
							      CString&				nodeValue);

	//判断xml节点是否是孩子
	static bool JudgeTerminateNode(IXMLDOMNode* pXMLNode);

	BOOL ReadRegWinXml(const std::string& fileName,std::vector<RegWinInfo>& vecRWI);

	//xml格式的签名
	BOOL MakeSignXML(std::string szFile,
		             std::string szInData, 
					 std::string szOutSignData,
					 std::string szHashData,
					 std::string szCert,
					 std::string& szxml);

	BOOL CXMLDOMParser::PutValue(IXMLDOMElement* pIXMLElem,std::string szName,std::string szData);

	
	BOOL LoadXml(const char* szXml, IXMLDOMElement*&	pIXMLElem);
	void RemoveNodeAttr(IXMLDOMElement* pEle, const char* szAttr);

protected:
private:
	IXMLDOMDocument2*				m_pIXMLDoc;		// XML文档
	CString  m_fileName;   //文件的名称；
	bool m_bSave ; //是否需要保存
	

};

#endif