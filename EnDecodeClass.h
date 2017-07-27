#pragma once
#include <string>

class CEnDecodeClass
{
public:
	CEnDecodeClass(void);
	~CEnDecodeClass(void);

	static int Gbk2Utf(std::string &szString);
	static int Utf2Gbk(std::string &szString);
	static void		SplitByWordTrimW(const std::wstring &szSrc, std::wstring tok, std::vector<std::wstring> &v_out);
	static int		TrimStringW(std::wstring& wszString);
	static void		StringReplaceW(std::wstring &szReplaceStr, const std::wstring &szSrcWord, const std::wstring &szDestWord);

	static std::wstring StringA2W(std::string str);
	static std::string	StringW2A(std::wstring wstr);
};

void StringReplace(std::string &szReplaceStr, const std::string &szSrcWord, const std::string &szDestWord) ;
std::string FormatJsonToString(std::string &szJsonStr);
std::string FormatStringToJson(std::string &szJsonStr);