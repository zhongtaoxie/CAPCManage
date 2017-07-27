#include "StdAfx.h"
#include "EnDecodeClass.h"

void StringReplace(std::string &szReplaceStr, const std::string &szSrcWord, const std::string &szDestWord)  
{  
	std::string::size_type pos = 0;  
	std::string::size_type srclen = szSrcWord.size();  
	std::string::size_type dstlen = szDestWord.size();  

	while( (pos=szReplaceStr.find(szSrcWord, pos)) != std::string::npos )  
	{  
		szReplaceStr.replace( pos, srclen, szDestWord );  
		pos += dstlen;  
	}  
} 

std::string FormatJsonToString(std::string &szJsonStr)
{
	if (szJsonStr.empty())
		return szJsonStr;

	StringReplace(szJsonStr, std::string("&lt;"), std::string("<"));
	StringReplace(szJsonStr, std::string("&gt;"), std::string(">"));
	StringReplace(szJsonStr, std::string("&quot;"), std::string("\""));
	StringReplace(szJsonStr, std::string("&#39;"), std::string("\'"));
	StringReplace(szJsonStr, std::string("&nbsp;"), std::string(" "));

	return szJsonStr;
}

std::string FormatStringToJson(std::string &szJsonStr)
{
	if (szJsonStr.empty())
		return szJsonStr;

	StringReplace(szJsonStr, std::string("<"), std::string("&lt;"));
	StringReplace(szJsonStr, std::string(">"), std::string("&gt;"));
	StringReplace(szJsonStr, std::string("\""), std::string("&quot;"));
	StringReplace(szJsonStr, std::string("\'"), std::string("&#39;"));
	StringReplace(szJsonStr, std::string(" "), std::string("&nbsp;"));

	return szJsonStr;
}


CEnDecodeClass::CEnDecodeClass(void)
{
}

CEnDecodeClass::~CEnDecodeClass(void)
{
}

int CEnDecodeClass::Gbk2Utf(std::string &szString)
{
	wchar_t	*pUtfBuf_w;
	char	*pUtfBuf_a;
	int		nBufLen;

	if (szString.empty())
		return 1;

	nBufLen = MultiByteToWideChar(CP_ACP, 0, szString.c_str(), -1, NULL, 0);
	pUtfBuf_w = new wchar_t[nBufLen +1];
	memset(pUtfBuf_w, 0, sizeof(WCHAR)*(nBufLen + 1));
	MultiByteToWideChar(CP_ACP, 0, szString.c_str(), -1, pUtfBuf_w, nBufLen);

	nBufLen = WideCharToMultiByte(CP_UTF8, 0, pUtfBuf_w, -1, NULL, 0, NULL, NULL);
	pUtfBuf_a = new char[nBufLen + 1];
	memset(pUtfBuf_a, 0, sizeof(char)*(nBufLen + 1));
	WideCharToMultiByte(CP_UTF8, 0, pUtfBuf_w, -1, pUtfBuf_a, nBufLen, NULL, NULL);

	szString = pUtfBuf_a;
	if (pUtfBuf_a)
		delete [] pUtfBuf_a;
	if (pUtfBuf_w)
		delete [] pUtfBuf_w;
	return 0;
}

int CEnDecodeClass::Utf2Gbk(std::string &szString)
{
	if (szString.empty())
		return 1;

	std::string strTemp = "";
	int len = MultiByteToWideChar(CP_UTF8, 0, szString.c_str(), -1, NULL, 0);  
	unsigned short * wszGBK = new unsigned short[len + 1];  
	memset(wszGBK, 0, len * 2 + 2);  
	MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)szString.c_str(), -1, (LPWSTR)wszGBK, len);  

	len = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)wszGBK, -1, NULL, 0, NULL, NULL);  
	char *szGBK = new char[len + 1];  
	memset(szGBK, 0, len + 1);  
	len = WideCharToMultiByte(CP_ACP,0, (LPCWSTR)wszGBK, -1, szGBK, len, NULL, NULL);  
	szString = szGBK;
	delete[]szGBK;  
	delete[]wszGBK;
	return 0;
}

void CEnDecodeClass::SplitByWordTrimW(const std::wstring &szSrc, std::wstring tok, std::vector<std::wstring> &v_out)
{
	v_out.clear();
	std::wstring wszTempString;
	if (szSrc.empty() || tok.empty())
		return;

	int index = 0,pre_index=0,len = 0;
	do 
	{
		index = szSrc.find(tok, pre_index);
		if (index == std::wstring::npos)
		{
			wszTempString = szSrc.substr(pre_index);
			TrimStringW(wszTempString);
			v_out.push_back(wszTempString);
			pre_index = 0;
		}else
		{
			wszTempString = szSrc.substr(pre_index,  index - pre_index);
			TrimStringW(wszTempString);
			v_out.push_back(wszTempString);
			pre_index = index + 1;
		}
	} while (pre_index > 0);
}


int CEnDecodeClass::TrimStringW(std::wstring& wszString)
{
	StringReplaceW(wszString, L" ", L"");
	StringReplaceW(wszString, L"\n", L"");
	StringReplaceW(wszString, L"\r", L"");
	return 0;
}

void CEnDecodeClass::StringReplaceW(std::wstring &szReplaceStr, const std::wstring &szSrcWord, const std::wstring &szDestWord)
{
	std::wstring::size_type pos = 0;  
	std::wstring::size_type srclen = szSrcWord.size();  
	std::wstring::size_type dstlen = szDestWord.size();  

	while( (pos=szReplaceStr.find(szSrcWord, pos)) != std::wstring::npos )  
	{  
		szReplaceStr.replace( pos, srclen, szDestWord );  
		pos += dstlen;  
	}  

}

//ANSIתunicode
std::wstring CEnDecodeClass::StringA2W(std::string str)
{
	std::wstring wszRet = L"";
	DWORD dwNum = MultiByteToWideChar (CP_ACP, 0, str.c_str(), -1, NULL, 0);
	wchar_t *pwText;
	pwText = new wchar_t[dwNum];
	if(!pwText)
	{
		return L"";
	}
	MultiByteToWideChar (CP_ACP, 0, str.c_str(), -1, pwText, dwNum);
	wszRet = pwText;
	delete [] pwText;
	return wszRet;
}

//Unicodeתansi
std::string CEnDecodeClass::StringW2A(std::wstring wstr)
{
	std::string szRet = "";
	DWORD dwNum = WideCharToMultiByte(CP_OEMCP,NULL,wstr.c_str(),-1,NULL,0,NULL,FALSE);
	char *psText;
	psText = new char[dwNum];
	if(!psText)
	{
		return "";
	}
	WideCharToMultiByte (CP_OEMCP,NULL,wstr.c_str(),-1,psText,dwNum,NULL,FALSE);
	szRet = psText;
	delete []psText;
	return szRet;
}