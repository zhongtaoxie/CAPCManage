
#include "MQ_Log.h"
#include "MQ_Defines.h"
#include "MQ_TimeValue.h"
#include "MQ_Thread.h"

#include <fstream>
#include <cassert>

#define LOG_GUARD( lockable )   Lock lock(lockable);(void)lock

CLog* CLog::mpInstance = NULL;
Mutex CLog::mMutexInst;

int CLog::mMaxLine = 50000;
LEVEL CLog::mLimitLevel = LOG_NONE ;
CLog::TYPE  CLog::mType = CLog::NONE;

string  CLog::mFilePath;
string  CLog::mFileName = "log";
unsigned CLog::mFlag;

const char
CLog::_descriptions[][32] = {"-NONE: ","-CRIT: ","-ERROR: ", "-WARNING: ", "-INFO: ", "-DEBUG: "}; 
const int CLog::_descriptions_length[] ={0,7,8,10,7,8};

CLog::CLog(void):mCurrentLines(0),mFileCount(1),mpLogger(0)
{
}

CLog::~CLog(void)
{
}


void CLog::initialize(TYPE t, LEVEL l, int maxline,const string& filepath,const string& appname)
{
   initialize(t,l,maxline,
	          COL_DATE |COL_TIME|COL_MICROSEC|COL_PROC|COL_THREAD,
	          filepath,
	          appname);
}

void CLog::initialize(TYPE t, LEVEL l, int maxline,unsigned columnsetting,const string& filepath,const string& appname)
{
    CLog::mLimitLevel = l;
    CLog::mType = t;
    CLog::mFilePath = filepath;
    CLog::mFileName = appname;
	mFlag = columnsetting;
	mMaxLine = maxline;
	if ( t == CLog::FILE && filepath.empty() )
	{
		CLog::mFilePath = ".";
	}
}


CLog* CLog::getInstance()
{
    //首次创建日志文件
    if (NULL == CLog::mpInstance)
	{
		LOG_GUARD(mMutexInst);

	    mpInstance = new CLog();
		mpInstance->newLogFile(CLog::mFilePath,CLog::mFileName);

	}
	else //日志文件已经创建
	{
		LOG_GUARD(mMutexInst);
	    //如果文件行数已经达到行数限制，则切分日志文件(先关闭原文件，再重建新文件)
        if ( CLog::mMaxLine && mpInstance->mCurrentLines >= CLog::mMaxLine)
        {
            mpInstance->closeLogFile();
            mpInstance->newLogFile(CLog::mFilePath,CLog::mFileName);
        }
	}

    return CLog::mpInstance;
}


void CLog::release()
{
	LOG_GUARD(mMutexInst);
	closeLogFile();

    delete this;
	
	mpInstance = NULL;
}

void CLog::closeLogFile()
{
	if (CLog::mType != CLog::FILE) 
		return;

	if ( mpLogger )
	{
        mpLogger->seekp(0, ios_base::beg);

        //added by ligang to close file
        delete mpLogger;
        mpLogger = NULL;
    }

	mCurrentLines = 0;

}

void CLog::newLogFile(const string& path,const string& appname)
{
	if (CLog::mType != CLog::FILE) 
		return;

	assert(NULL == mpLogger);

    //SYSTEMTIME t;
	//GetLocalTime( &t );

	MQTimeValue tv = MQTimeValue::getTimeOfDay();
    struct tm *local_time;
	time_t now = tv.getSec();
    local_time = localtime((time_t*)&now);

	char szPathFile[128]={0};
	mpInstance->mCurrentLines = 0;

    long pid = getpid();

    local_time->tm_mon += 1;
	//snprintf(szPathFile,128,"%s/%s_%04d%02d%02d_%02d%02d%02d_%03d_%d_%d.log",
	//文件命名规则: APP_yyyymmdd_hhmmss_pid_seq.log
	snprintf(szPathFile,128,"%s/%s_%04d%02d%02d_%02d%02d%02d_%lu_%03d.log",
		path.c_str(),
		appname.c_str(),
		local_time->tm_year+1900,
		local_time->tm_mon,
		local_time->tm_mday,
		local_time->tm_hour,
		local_time->tm_min,
		local_time->tm_sec,
		//tv.getUsec(),
		pid,
		mFileCount++);

	mpLogger = new std::ofstream(szPathFile, std::ios_base::out | std::ios_base::trunc);

}


void CLog::printLog(LEVEL lvl,const char* promft,const char* format_str,va_list& marker)
{

    //LOG_GUARD(mMutexWriting);

	char szLog[MAX_LINE_LENGTH] = {0};
	int nPos = 0;
	if ( mFlag )
	{
	   szLog[nPos++] = SettingOpenChar;
	}

	MQTimeValue tv = MQTimeValue::getTimeOfDay();
    struct tm *local_time;
	time_t now = tv.getSec();
    local_time = localtime((time_t*)&now);
    local_time->tm_mon += 1;

    if ( mFlag & COL_DATE )
	{
		snprintf( szLog+nPos,MAX_LINE_LENGTH-1-nPos,"%04d-%02d-%02d",local_time->tm_year+1900,local_time->tm_mon,local_time->tm_mday);
		nPos+=10;
	}

	if ( mFlag & COL_TIME )
	{
		snprintf( szLog+nPos,MAX_LINE_LENGTH-1-nPos," %02d:%02d:%02d",local_time->tm_hour,local_time->tm_min,local_time->tm_sec );
		nPos+=9;
	}

	if ( mFlag & COL_MICROSEC )
	{
		snprintf( szLog+nPos,MAX_LINE_LENGTH-1-nPos,".%03lu",tv.getUsec() );
		nPos+=4;
	}
    
	if ( mFlag & COL_PROC )
	{
		snprintf( szLog+nPos,MAX_LINE_LENGTH-1-nPos," P%d",ThreadIf::selfPid());
		nPos += (int)strlen(szLog+nPos);
	}

	if ( mFlag & COL_THREAD )
	{
		snprintf( szLog+nPos,MAX_LINE_LENGTH-1-nPos," T%lu", ThreadIf::selfId() );//lint !e1015 !e10 huangliang
		nPos += (int)strlen(szLog+nPos);
	}

	if ( mFlag )
	{
	   szLog[nPos++] = SettingCloseChar;
	}

	 snprintf( szLog+nPos,MAX_LINE_LENGTH-1-nPos,"%s",_descriptions[lvl]);
	 nPos+=_descriptions_length[lvl];

	 if ( promft )
	 {
		 size_t promftlen = strlen(promft);
	     snprintf( szLog+nPos,MAX_LINE_LENGTH-1-nPos,"%s",promft);
	     nPos+=(int)promftlen;	 
	 }

	vsnprintf( szLog+nPos,MAX_LINE_LENGTH-1-nPos,format_str,marker);

  	if (mType ==  CLog::FILE)
	{
		LOG_GUARD(mMutexInst);//lint !e578 huanligang
         {
            LOG_GUARD(mMutexWriting);
		(*mpLogger)<<szLog<<std::endl;
		mpLogger->flush();
		    mpLogger->clear();

        //已经写入的文件行数自增长1
        CLog::mCurrentLines++;		
	}
    }
	else if (mType == CLog::STDIO)
	{
        LOG_GUARD(mMutexWriting);
		std::cout<<szLog<<std::endl;
	
	}
	else if (mType == CLog::VSDEBUGWINDOW)
	{
#ifdef WIN32
         LOG_GUARD(mMutexWriting);
		::OutputDebugStringA(szLog);//lint !e40 huangliang
        ::OutputDebugStringA("\r\n");//lint !e40 huangliang
#endif
	}
}

void CLog::print_LOG_NONE(const char *format, ...)
{
   return;
}

void CLog::print_LOG_CRIT(const char *format, ...)
{
	if ( LOG_CRIT > mLimitLevel )
	{
	    return;
	}

    va_list arg;
    va_start(arg, format);
    printLog(LOG_CRIT,0 , format, arg);
    va_end(arg);  
}

void CLog::print_LOG_ERROR(const char *format, ...)
{
	if ( LOG_ERROR > mLimitLevel )
	{
	    return;
	}
    va_list arg;
    va_start(arg, format);
    printLog(LOG_ERROR,0 , format, arg);
    va_end(arg);  
}

void CLog::print_LOG_WARNING(const char *format, ...)
{
	if ( LOG_WARNING > mLimitLevel )
	{
	    return;
	}
    va_list arg;
    va_start(arg, format);
    printLog(LOG_WARNING,0 , format, arg);
    va_end(arg); 

}

void CLog::print_LOG_INFO(const char *format, ...)
{
	if ( LOG_INFO > mLimitLevel )
	{
	    return;
	}
    va_list arg;
    va_start(arg, format);
    printLog(LOG_INFO,0 , format, arg);
    va_end(arg); 

}

void CLog::print_LOG_DEBUG(const char *format, ...)
{
	if ( LOG_DEBUG > mLimitLevel )
	{
	    return;
	}
    va_list arg;
    va_start(arg, format);
    printLog(LOG_DEBUG,0 , format, arg);
    va_end(arg); 

}

void CLog::promft_LOG_NONE(const char* pmft,const char *format, ...)
{
   return;
}

void CLog::promft_LOG_CRIT(const char* pmft,const char *format, ...)
{
	if ( LOG_CRIT > mLimitLevel )
	{
	    return;
	}
    va_list arg;
    va_start(arg, format);
    printLog(LOG_CRIT,pmft , format, arg);
    va_end(arg);  
}

void CLog::promft_LOG_ERROR(const char* pmft,const char *format, ...)
{
	if ( LOG_ERROR > mLimitLevel )
	{
	    return;
	}
    va_list arg;
    va_start(arg, format);
    printLog(LOG_ERROR,pmft , format, arg);
    va_end(arg);  
}





void CLog::promft_LOG_WARNING(const char* pmft,const char *format, ...)
{
	if ( LOG_WARNING > mLimitLevel )
	{
	    return;
	}
    va_list arg;
    va_start(arg, format);
    printLog(LOG_WARNING,pmft , format, arg);
    va_end(arg); 

}

void CLog::promft_LOG_INFO(const char* pmft,const char *format, ...)
{
	if ( LOG_INFO > mLimitLevel )
	{
	    return;
	}
    va_list arg;
    va_start(arg, format);
    printLog(LOG_INFO,pmft , format, arg);
    va_end(arg); 

}

void CLog::promft_LOG_DEBUG(const char* pmft,const char *format, ...)
{
	if ( LOG_DEBUG > mLimitLevel )
	{
	    return;
	}
    va_list arg;
    va_start(arg, format);
    printLog(LOG_DEBUG,pmft , format, arg);
    va_end(arg); 

}







