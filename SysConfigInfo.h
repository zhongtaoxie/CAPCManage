#ifndef __SYS_CONFIG_INFO_H_
#define __SYS_CONFIG_INFO_H_
#pragma once

#include <LMACCESS.H>
#include <LMERR.H>
#include <LMAPIBUF.H>
#include <vector>
using namespace std;


//U≈Ã≤Â∞Œ∫Õπ≤œÌ¥≈≈Ãº‡øÿ
typedef struct STRUCT_DISK_INFO
{
	std::string sDisk;//≈Ã∑˚
	std::string sType;// «USBªπ «share
}struDiskInfo;


class CDiscInfo
{
public:
	CDiscInfo(){};
	~CDiscInfo(){m_vecDiskInfo.clear();};

	LRESULT OnDeviceChange(HWND hwnd,WPARAM wParam, LPARAM lParam);
	char FirstDriveFromMask(ULONG unitmask);
	BOOL  SendDiscJson(const std::string& sDiskStr,const std::string& sAction);

	vector<struDiskInfo> m_vecDiskInfo;

};

#endif