#include <windows.h>
#include <winioctl.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <set>
#include <dontuse.h>

#define CLIENT_SIDE
#include "../FileSystemDriver/FileSystemDriver.h"
#include "ProcInfo.h"

BOOL EnableDebugPrivilege(BOOL enable)
{
	HANDLE hToken = NULL;
	LUID luid;

	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		std::wcout << L"Can't open current process token, errorcode: " << ::GetLastError() << std::endl;
		return FALSE;
	}
		
	if (!::LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		std::wcout << L"Can't get current privileges, errorcode: " << ::GetLastError() << std::endl;
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
		std::wcout << L"Can't adjust privileges, errorcode: " << ::GetLastError() << std::endl;
		return FALSE;
	}

	return TRUE;
}

int _cdecl main(_In_ int argc, _In_reads_(argc) char *argv[])
{
	if (!EnableDebugPrivilege(TRUE))
		std::wcout << L"Warning! Can't set SE_DEBUG_PRIVILEGE, monitoring for some processes will be unavailiable!" << std::endl;

	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		std::wcout << L"Error on CreateToolhelp32Snapshot call. Errorcode: " << ::GetLastError() << std::endl;
		return -1;
	}

	PROCESSENTRY32 proc;
	proc.dwSize = sizeof(PROCESSENTRY32);
	std::set<ProcessInfo> procInfo;

	if (!::Process32FirstW(hSnapshot, &proc))
	{
		std::wcout << L"Error on Process32FirstW call. Errorcode: " << ::GetLastError() << std::endl;
		::CloseHandle(hSnapshot);
		return -2;
	}

	HANDLE hProcess = NULL;
	wchar_t image_path[MAX_PATH];

	do
	{
		memset(image_path, 0, sizeof(wchar_t)* MAX_PATH);
		hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, 0, proc.th32ProcessID);
		if (hProcess == NULL)
		{
			std::wcout << L"Warning! Can't open process with PID: " << int(proc.th32ProcessID) << L" error: " << ::GetLastError() << std::endl;
			continue;
		}

		if (::GetModuleFileNameExW(hProcess, 0, image_path, MAX_PATH) == 0)
		{
			std::wcout << L"Warning! Can't get process path with PID: " << int(proc.th32ProcessID) << L" error: " << ::GetLastError() << std::endl;
			::CloseHandle(hProcess);
			continue;
		}

		::CloseHandle(hProcess);

		procInfo.insert(ProcessInfo((int)proc.th32ProcessID, image_path));
	} while (::Process32NextW(hSnapshot, &proc));

	::CloseHandle(hSnapshot);
	if (!EnableDebugPrivilege(FALSE))
		std::wcout << L"Warning! Can't drop SE_DEBUG_PRIVILEGE!" << std::endl;

	for (std::set<ProcessInfo>::iterator i = procInfo.begin(); i != procInfo.end(); i++)
		std::wcout << i->getPid() << L" " << i->getPath() << std::endl;

	int target = -1;
	std::wcout << L"Write PID of choosen process:" << std::endl;
	std::wcin >> target;

	if (std::find(procInfo.begin(), procInfo.end(), ProcessInfo(target, L"")) == procInfo.end())
	{
		std::wcout << L"Incorrect PID!" << std::endl;
		return -3;
	}

	std::wcout << std::endl;

	HANDLE port = NULL;
	HRESULT hr;
	DWORD bytes_returned;
	MESSAGE_STRUCT message;

	//
	//  Open a commuication channel to the filter
	//

	std::wcout << L"Connecting to the filter ..." << std::endl;
	hr = FilterConnectCommunicationPort(L"\\FileSystemDriver", 0, NULL, 0, NULL, &port);
	if (IS_ERROR(hr))
	{
		std::wcout << L"ERROR: Connecting to filter port:" << std::hex << hr << std::endl;
		return -4;
	}

	for (;;) {
		int status = FilterGetMessage(port, (PFILTER_MESSAGE_HEADER)&message, sizeof(MESSAGE_STRUCT), NULL);
		std::wcout << L"op: " << int(message.body.ioOpType) << std::endl;
		std::wcout << L"guid: " << message.body.guid << std::endl;
		std::wcout << L"path: " << message.body.path << std::endl << std::endl;
	}

	/* example
	for (;;) {
		fgets(buf, sizeof(buf), stdin);
		if (strcmp(buf, "exit\n") == 0)
			break;
		FilterSendMessage(port, buf, strlen(buf), out_buf, sizeof(out_buf), &bytes_returned);
		out_buf[bytes_returned] = 0;
		printf("%d bytes returned: %s\n", bytes_returned, out_buf);
	}*/

	CloseHandle(port);
	return hr;
}

