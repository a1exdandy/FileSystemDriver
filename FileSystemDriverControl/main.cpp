#include <windows.h>
#include <fltuser.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <fstream>
#include <set>
#include <dontuse.h>
#include <ctime>

#define CLIENT_SIDE
#include "../FileSystemDriver/FileSystemDriver.h"
#include "ProcInfo.h"

//timeout for WaitForSingleObject
#define MSG_WAIT_TIMEOUT 1000

//Global close flag
BOOL gCloseFlag = FALSE;

BOOL SetMaxConsoleSize()
{
	HANDLE console = ::GetStdHandle(STD_OUTPUT_HANDLE);
	if (console == INVALID_HANDLE_VALUE)
	{
		std::wcerr << L"Warning! Can't get output device handle! Errorcode: " << ::GetLastError() << std::endl;
		return FALSE;
	}

	CONSOLE_SCREEN_BUFFER_INFO cInfo;
	memset(&cInfo, 0, sizeof(CONSOLE_SCREEN_BUFFER_INFO));

	if (!::GetConsoleScreenBufferInfo(console, &cInfo))
	{
		std::wcerr << L"Warning! Can't get console info! Errorcode: " << ::GetLastError() << std::endl;
		return FALSE;
	}

	cInfo.dwSize.Y = MAXSHORT - 1;

	if (!::SetConsoleScreenBufferSize(console, cInfo.dwSize))
	{
		std::wcerr << L"Warning! Can't set console screen buffer size! Errorcode: " << ::GetLastError() << std::endl;
		return FALSE;
	}

	return TRUE;
}

BOOL EnableDebugPrivilege(_In_ BOOL enable)
{
	HANDLE hToken = NULL;
	LUID luid;

	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		std::wcerr << L"Warning! Can't open current process token, errorcode: " << ::GetLastError() << std::endl;
		return FALSE;
	}
		
	if (!::LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		std::wcerr << L"Warning! Can't get current privileges, errorcode: " << ::GetLastError() << std::endl;
		return FALSE;
	}

	TOKEN_PRIVILEGES tokenPriv;
	tokenPriv.PrivilegeCount = 1;
	tokenPriv.Privileges[0].Luid = luid;
	if (enable)
		tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tokenPriv.Privileges[0].Attributes = 0;

	if (!::AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		std::wcerr << L"Warning! Can't adjust privileges, errorcode: " << ::GetLastError() << std::endl;
		return FALSE;
	}

	return TRUE;
}

BOOL CtrlHandler(_In_ DWORD fdwCtrlType)
{
	if ((fdwCtrlType == CTRL_C_EVENT) || (fdwCtrlType == CTRL_CLOSE_EVENT) || (fdwCtrlType == CTRL_BREAK_EVENT))
	{
		gCloseFlag = TRUE;
		return TRUE;
	}

	return FALSE;
}

void MessageOutput(_In_ std::wofstream& sFile, _In_ MESSAGE_STRUCT& msg, _In_ std::set<ProcessInfo>& processes)
{
	std::wstring messageType;
	switch (int(msg.body.messageType.operationStatus.ioOpType))
	{
	case 0:
		messageType = std::wstring(L"IRP_MJ_CREATE");
		break;
	case 3:
		messageType = std::wstring(L"IRP_MJ_READ");
		break;
	case 4:
		messageType = std::wstring(L"IRP_MJ_WRITE");
		break;
	default:
		messageType = std::to_wstring(int(msg.body.messageType.operationStatus.ioOpType));
		break;
	}

	std::wstring procPath = std::wstring(L"Not available");
	std::set<ProcessInfo>::iterator targetProc;
	targetProc = std::find(processes.begin(), processes.end(), ProcessInfo((int) msg.body.messageType.operationStatus.pid, L""));
	if (targetProc != processes.end())
		procPath = targetProc->getPath();

	time_t rawtime;
	tm timestruct;
	time(&rawtime);
	localtime_s(&timestruct, &rawtime);

	WCHAR mountPoint[MAX_PATH];
	memset(mountPoint, 0, sizeof(WCHAR) * MAX_PATH);
	DWORD recevied = 0;
	std::wstring volumePath = L"\\\\" + std::wstring(msg.body.messageType.operationStatus.guid + 2) + L"\\";

	if ((::GetVolumePathNamesForVolumeNameW(volumePath.c_str(), mountPoint, MAX_PATH, &recevied)) && (recevied > 0))
		volumePath = std::wstring(mountPoint);
	else if (::GetLastError() != ERROR_MORE_DATA)
		std::wcerr << L"Warning! Can't resolve guid to mount point, guid used as path. Errorcode: " << ::GetLastError() << std::endl;

	if (sFile.is_open())
	{
		sFile << timestruct.tm_hour << L":" << timestruct.tm_min << L":" << timestruct.tm_sec << L";";
		sFile << timestruct.tm_mday << L"." << timestruct.tm_mon + 1 << L"." << timestruct.tm_year + 1900 << L";";
		sFile << msg.body.messageType.operationStatus.pid << L";" << procPath << L";";
		sFile << messageType << L";";
		sFile << volumePath + std::wstring(msg.body.messageType.operationStatus.path) << L";" << std::endl;
	}

	std::wcout << L"PID: " << msg.body.messageType.operationStatus.pid << std::endl;
	std::wcout << L"op: " << messageType << std::endl;
	std::wcout << L"path: " << volumePath + std::wstring(msg.body.messageType.operationStatus.path) << std::endl << std::endl;
}

int _cdecl main(_In_ int argc, _In_reads_(argc) char *argv[])
{
	if (!SetMaxConsoleSize())
		std::wcerr << L"Warning! Can't set large console window size!" << std::endl;

	if (!EnableDebugPrivilege(TRUE))
		std::wcerr << L"Warning! Can't set SE_DEBUG_PRIVILEGE, monitoring for some processes will be unavailiable!" << std::endl;

	if (!::SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE))
	{
		std::wcerr << L"Error! Can't set console ctrl handler. Errorcode: " << ::GetLastError() << std::endl;
		return -1;
	}

	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		std::wcerr << L"Error on CreateToolhelp32Snapshot call. Errorcode: " << ::GetLastError() << std::endl;
		return -2;
	}

	PROCESSENTRY32 proc;
	proc.dwSize = sizeof(PROCESSENTRY32);
	std::set<ProcessInfo> procInfo;

	if (!::Process32FirstW(hSnapshot, &proc))
	{
		std::wcerr << L"Error! Process32FirstW fails. Errorcode: " << ::GetLastError() << std::endl;
		::CloseHandle(hSnapshot);
		return -3;
	}

	HANDLE hProcess = NULL;
	wchar_t image_path[MAX_PATH];

	do
	{
		memset(image_path, 0, sizeof(wchar_t)* MAX_PATH);
		hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, 0, proc.th32ProcessID);
		if (hProcess == NULL)
		{
			std::wcerr << L"Warning! Can't open process with PID: " << int(proc.th32ProcessID) << L" error: " << ::GetLastError() << std::endl;
			continue;
		}

		if (::GetModuleFileNameExW(hProcess, 0, image_path, MAX_PATH) == 0)
		{
			std::wcerr << L"Warning! Can't get process path with PID: " << int(proc.th32ProcessID) << L" error: " << ::GetLastError() << std::endl;
			::CloseHandle(hProcess);
			continue;
		}

		::CloseHandle(hProcess);

		procInfo.insert(ProcessInfo((int)proc.th32ProcessID, image_path));
	} while (::Process32NextW(hSnapshot, &proc));

	::CloseHandle(hSnapshot);
	
	if (!EnableDebugPrivilege(FALSE))
		std::wcerr << L"Warning! Can't drop SE_DEBUG_PRIVILEGE!" << std::endl;

	for (std::set<ProcessInfo>::iterator i = procInfo.begin(); i != procInfo.end(); i++)
		std::wcout << i->getPid() << L" " << i->getPath() << std::endl;
	std::wcout << L"* All processes monitoring" << std::endl;

	int target = -1;
	std::wcout << L"Write PID of choosen process:" << std::endl;
	std::wcin >> target;

	std::set<ProcessInfo>::iterator targetProc;
	if (target != -1)
	{
		targetProc = std::find(procInfo.begin(), procInfo.end(), ProcessInfo(target, L""));
		if (targetProc == procInfo.end())
		{
			std::wcerr << L"Error! Incorrect PID!" << std::endl;
			return -4;
		}
	}

	std::wcout << std::endl;

	HANDLE port = INVALID_HANDLE_VALUE;
	HRESULT hr;
	DWORD bytes_returned;
	std::wofstream fileOut;

	if (argc > 1)
	{
		try
		{
			fileOut.open(argv[1], std::wofstream::app);
		}
		catch (std::wofstream::failure e)
		{
			std::wcerr << L"Warning! Can't open log file. Errorcode: " << e.code().value() << std::endl;
		}
	}

	//  Open a commuication channel to the filter

	std::wcout << L"Connecting to the filter ..." << std::endl;
	hr = FilterConnectCommunicationPort(L"\\FileSystemDriver", 0, NULL, 0, NULL, &port);
	if (IS_ERROR(hr))
	{
		std::wcerr << L"Error! Connecting to filter port fails:" << std::hex << hr << std::endl;
		if (fileOut.is_open())
			fileOut.close();
		return -5;
	}

	OVERLAPPED overlap;
	memset(&overlap, 0, sizeof(OVERLAPPED));
	overlap.hEvent = ::CreateEvent(NULL, FALSE, FALSE, NULL);
	
	time_t rawtime;
	tm timestruct;
	
	if (fileOut.is_open())
	{
		time(&rawtime);
		localtime_s(&timestruct, &rawtime);
		fileOut << L"Capturing started:;";
		fileOut << timestruct.tm_hour << L":" << timestruct.tm_min << L":" << timestruct.tm_sec << L";";
		fileOut << timestruct.tm_mday << L"." << timestruct.tm_mon + 1 << L"." << timestruct.tm_year + 1900;
		fileOut << L";PID:;";
		if (target == -1)
			fileOut << L"All;" << std::endl;
		else
			fileOut << target << L";Path:;" << targetProc->getPath() << L";" << std::endl;
		fileOut << L"Time;Date;Process ID;Process path;Operation;File path;" << std::endl;
	}

	MESSAGE_STRUCT message;

	message.body.messageType.processPid.pid = target;
	HRESULT hResult = FilterSendMessage(port, &message.body, sizeof(message.body), &message.body, sizeof(message.body), &bytes_returned);
	if ((message.body.messageType.driverReply.status != 0) || IS_ERROR(hResult))
	{
		std::wcerr << L"ERROR: Can't set pid.";
		if (IS_ERROR(hResult))
			std::wcerr << L" Send message fails with errorcode: " << hResult;
		else
			std::wcerr << L" Incorrect driver answer!" << std::endl;
		std::wcerr << std::endl;

		if (fileOut.is_open())
			fileOut.close();
		::CloseHandle(port);
		return -6;
	}

	std::wcout << L"Listening... " << std::endl;
	
	while (!gCloseFlag)
	{
		if (HRESULT_FROM_WIN32(ERROR_IO_PENDING) != FilterGetMessage(port, (PFILTER_MESSAGE_HEADER)&message, sizeof(MESSAGE_STRUCT), &overlap))
		{
			std::wcerr << L"Error! FilterGetMessage fails with errorcode: " << ::GetLastError() << std::endl;
			break;
		}
		
		DWORD status = WAIT_TIMEOUT;
		while ((status == WAIT_TIMEOUT) && (!gCloseFlag))
			status = ::WaitForSingleObject(overlap.hEvent, MSG_WAIT_TIMEOUT);
		
		if (gCloseFlag)
		{
			std::wcout << L"Closed by user." << std::endl;
			break;
		}
				
		if (status != WAIT_OBJECT_0)
		{
			std::wcerr << L"Error! WaitForSingleObject fails with errorcode: " << ::GetLastError() << std::endl;
			break;
		}
	
		MessageOutput(fileOut, message, procInfo);
	}

	if (fileOut.is_open())
	{
		time(&rawtime);
		localtime_s(&timestruct, &rawtime);
		fileOut << L"Capturing stopped:;";
		fileOut << timestruct.tm_hour << L":" << timestruct.tm_min << L":" << timestruct.tm_sec << L";";
		fileOut << timestruct.tm_mday << L"." << timestruct.tm_mon + 1 << L"." << timestruct.tm_year + 1900 << L";" << std::endl;
		fileOut.close();
	}
	::CloseHandle(port);
	::CloseHandle(overlap.hEvent);

	return 0;
}

