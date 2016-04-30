/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

scanUser.c

Abstract:

This file contains the implementation for the main function of the
user application piece of scanner.  This function is responsible for
actually scanning file contents.

Environment:

User mode

--*/

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include <dontuse.h>
#include <wchar.h>

#define CLIENT_SIDE
#include "../FileSystemDriver/FileSystemDriver.h"

int _cdecl
main(
	_In_ int argc,
	_In_reads_(argc) char *argv[]
)
{
	HANDLE port = NULL;
	HRESULT hr;
	DWORD bytes_returned;
	MESSAGE_STRUCT message;
	

	//
	//  Open a commuication channel to the filter
	//

	printf("Connecting to the filter ...\n");
	hr = FilterConnectCommunicationPort(L"\\FileSystemDriver", 0, NULL, 0, NULL, &port);
	if (IS_ERROR(hr)) {
		printf("ERROR: Connecting to filter port: 0x%08x\n", hr);
		return -1;
	}

	for (;;) {
		int status = FilterGetMessage(port, (PFILTER_MESSAGE_HEADER)&message, sizeof(MESSAGE_STRUCT), NULL);
		wprintf(L"op: %d\n", message.body.ioOpType);
		wprintf(L"guid: %s\n", message.body.guid);
		wprintf(L"path: %s\n\n", message.body.path);
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

