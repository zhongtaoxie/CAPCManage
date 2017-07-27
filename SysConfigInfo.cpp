#include "stdafx.h"
#include "SysConfigInfo.h"
#pragma comment(lib,"ws2_32.lib")
#define CDA_PRIVATE_FILE_NAME	"UEBAOption.ini"
#define TIMER_INTERVAL  60000

#include <iostream>
#include <Dbt.h>

#pragma  comment(lib,"Netapi32.lib")


char		g_UsbDisk[3]				= {0};									//保存U盘的盘符
int			g_nTmpCommandCount			= 0;
char*		g_sTmpCommandLine[32]		= {0};
char	g_diskListStr[128];



LRESULT CDiscInfo::OnDeviceChange(HWND hwnd,WPARAM wParam, LPARAM lParam)
{
	USES_CONVERSION;



	PDEV_BROADCAST_HDR lpdb = (PDEV_BROADCAST_HDR)lParam;
	switch(wParam)
	{
	case DBT_DEVICEARRIVAL:																							// 插入设备
		if (lpdb -> dbch_devicetype == DBT_DEVTYP_VOLUME)
		{
			PDEV_BROADCAST_VOLUME lpdbv = (PDEV_BROADCAST_VOLUME)lpdb;
			g_UsbDisk[0]			= FirstDriveFromMask(lpdbv ->dbcv_unitmask);												// 得到u盘盘符
			g_UsbDisk[1]			= ':';

			SendDiscJson(g_UsbDisk,"insert");
			
		}
		break;
	case DBT_DEVICEREMOVECOMPLETE:																					// 设备删除
		if (lpdb -> dbch_devicetype == DBT_DEVTYP_VOLUME)
		{
			PDEV_BROADCAST_VOLUME lpdbv = (PDEV_BROADCAST_VOLUME)lpdb;
			g_UsbDisk[0]			= FirstDriveFromMask(lpdbv ->dbcv_unitmask);												// 得到u盘盘符
			g_UsbDisk[1]			= ':';
			SendDiscJson(g_UsbDisk,"remove");
			
		}
		break;
	}
	return LRESULT();
}

char CDiscInfo::FirstDriveFromMask(ULONG unitmask)
{
	char i;
	for (i = 0; i < 26; ++i)
	{
		if (unitmask & 0x1)//看该驱动器的状态是否发生了变化
			break;
		unitmask = unitmask >> 1;
	}
	return (i + 'A');
}


BOOL	CDiscInfo::SendDiscJson(const std::string& sDiskStr,const std::string& sAction)
{
	
	int nType = GetDriveTypeA(sDiskStr.c_str());
	std::string		sDiskContent = "";
	struDiskInfo stInfo;

	switch(nType)
	{
	case DRIVE_REMOVABLE:
		{
			stInfo.sType = "Usb ";
			stInfo.sDisk = sDiskStr;
			m_vecDiskInfo.push_back(stInfo);
			break;
		}
		
	case DRIVE_REMOTE:
		{
			stInfo.sType = "Shard ";
			stInfo.sDisk = sDiskStr;
			m_vecDiskInfo.push_back(stInfo);
			break;
		}
	case DRIVE_CDROM:
		{
			stInfo.sType = "cdrom ";
			stInfo.sDisk = sDiskStr;
			m_vecDiskInfo.push_back(stInfo);
			break;
		}
	case DRIVE_NO_ROOT_DIR:
		{
			BOOL bFind = FALSE;
			vector<struDiskInfo>::iterator it = m_vecDiskInfo.begin();
			while(it != m_vecDiskInfo.end())
			{
				if (0 == sDiskStr.compare((*it).sDisk))
				{
					stInfo.sDisk = (*it).sDisk;
					stInfo.sType = (*it).sType;
					it = m_vecDiskInfo.erase(it);
					bFind = TRUE;
				}
				else
				{
					it++;
				}
			}
			if (!bFind)
			{
				return FALSE;
			}
			break;
		}

	default:
		return FALSE;
	//	break;
	}


	return TRUE;
}