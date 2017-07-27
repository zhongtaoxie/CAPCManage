#ifndef _ISTLOG_H_
#define _ISTLOG_H_
#pragma once

#include <stdio.h>
#include <iostream>
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/RollingFileAppender.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/PropertyConfigurator.hh"
#include "log4cpp/Win32DebugAppender.hh"


#pragma comment(lib,"ws2_32.lib")


#ifndef _LOG2CPP_PROJECT_

namespace log4cpp
{
	std::string	InitializeLog();
}

#ifdef _DLL

#ifdef _DEBUG
#pragma comment(lib,"log4cppD.lib")
#else
#pragma comment(lib,"log4cpp.lib")
#endif // _DEBUG


#else
 
#ifdef _DEBUG
#pragma comment(lib,"log4cppD_MT.lib")
#else
#pragma comment(lib,"log4cpp_MT.lib")
#endif // _DEBUG

#endif // _DEBUG
//*/

#endif



#define		LOG_FILE_NAME	"CDALog.log"
#define		KEY_LOG_LEVEL	"LogLevel"




#define LOG_ERROR(format,...)	log4cpp::Category::getRoot().getInstance(log4cpp::InitializeLog().c_str()).error(format,__VA_ARGS__)
#define LOG_WARN(format,...)	log4cpp::Category::getRoot().getInstance(log4cpp::InitializeLog().c_str()).warn(format,__VA_ARGS__)
#define LOG_NOTICE(format,...)	log4cpp::Category::getRoot().getInstance(log4cpp::InitializeLog().c_str()).notice(format,__VA_ARGS__)
#define LOG_INFO(format,...)	log4cpp::Category::getRoot().getInstance(log4cpp::InitializeLog().c_str()).info(format,__VA_ARGS__)
#define LOG_DEBUG(format,...)	log4cpp::Category::getRoot().getInstance(log4cpp::InitializeLog().c_str()).debug(format,__VA_ARGS__)



#endif