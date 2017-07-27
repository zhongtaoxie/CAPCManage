#ifndef __LOG_H__
#define __LOG_H__

#if _MSC_VER > 1000
#   pragma once
#endif

#include <string>
#include <iostream>
#include <fstream>

#include "MQ_Defines.h"
#include "MQ_Lockable.h"

using namespace std;

/*
 * 日志级别定义   
*/
typedef	enum
{
	LOG_NONE,    // 不打印
	LOG_CRIT,    // 导致异常的关键错误，这些异常可能会导致崩溃，系统不稳定等危险
	LOG_ERROR,   // 逻辑错误，导致功能没有正确实现的业务逻辑错误
	LOG_WARNING, // 告警，可能会导致逻辑错误的提示，但是不影响程序的正常执行
	LOG_INFO,    // 信息，业务逻辑的关键步骤信息
	LOG_DEBUG,   // 调试信息，用于分析排除错误的信息

} LEVEL;

/*
   通用的CLog日志打印类：

   1.可以限制打印日志的级别
   2.可以设置将日志打印到文件、控制台、Visual Stdio调试窗口
   3.可以定制日志的基本信息列，如日期、时间、毫秒级的时间、进程ID、线程ID等
   4.可以设置日志文件的最大行数，超过最大行数会重新生成一个新的日志文件
   
*/

class MQ_OS_EXPORT CLog
{

public:

	typedef enum
	{
	   NONE,
	   STDIO, // 打印到控制台
	   FILE,  // 打印到文件
	   VSDEBUGWINDOW, // 打印到Visual Stdio调试窗口 
	   
	} TYPE;

	typedef enum{
	
		COL_DATE = 0x1,      // 是否打印日期
		COL_TIME = 0x2,      // 是否打印时间
		COL_MICROSEC = 0x4,  // 是否打印毫秒
		COL_PROC = 0x8,      // 是否打印进程ID
		COL_THREAD = 0x16,   // 是否打印线程ID
                             // 是否打印
	
	} ColumnSetting;

	const static char SettingOpenChar = '[';
    const static char SettingCloseChar = ']';
	const static int MAX_LINE_LENGTH = 8192;
	static const char _descriptions[][32];
	static const int _descriptions_length[];

public:
	CLog(void);
	virtual ~CLog(void);

	static CLog* getInstance();
    void release();

	static void initialize(TYPE t, LEVEL l, int maxline,const string& filepath,const string& appname);
	static void initialize(TYPE t, LEVEL l, int maxline,unsigned columnsetting,const string& filepath,const string& appname);

	void print_LOG_NONE(const char *format, ...);
	void print_LOG_CRIT(const char *format, ...);
	void print_LOG_ERROR(const char *format, ...);
	void print_LOG_WARNING(const char *format, ...);
	void print_LOG_INFO(const char *format, ...);
	void print_LOG_DEBUG(const char *format, ...);

	void promft_LOG_NONE(const char* pmft,const char *format, ...);
	void promft_LOG_CRIT(const char* pmft,const char *format, ...);
	void promft_LOG_ERROR(const char* pmft,const char *format, ...);
	void promft_LOG_WARNING(const char* pmft,const char *format, ...);
	void promft_LOG_INFO(const char* pmft,const char *format, ...);
	void promft_LOG_DEBUG(const char* pmft,const char *format, ...);

private:

    void newLogFile(const string& path,const string& appname);
	void closeLogFile();

	void printLog(LEVEL lvl,const char* promft,const char* format_str,va_list& marker);

	static CLog* mpInstance;
	static Mutex mMutexInst;

	static int mMaxLine;
	int mCurrentLines;

	static LEVEL mLimitLevel;
	static TYPE  mType;
	static string  mFilePath;
	static string  mFileName;
	static unsigned mFlag;

	int mFileCount;
	std::ostream* mpLogger;
	std::string mCurrentFileName;
	
   
	Mutex mMutexWriting;
};


#define MQ_LOG(level,x)  do{ CLog::getInstance()->print_##level x ;}while(0)

#define DebugLog(x)   MQ_LOG(LOG_DEBUG,x)
#define ErrLog(x)     MQ_LOG(LOG_ERROR,x)
#define InfoLog(x)    MQ_LOG(LOG_INFO,x)
#define CritLog(x)    MQ_LOG(LOG_CRIT,x)
#define WarningLog(x) MQ_LOG(LOG_WARNING,x)

#endif //


