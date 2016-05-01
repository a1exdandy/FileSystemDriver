#include "FileSystemDriver.h"


NTSTATUS
ClientHandlerPortConnect(
_In_ PFLT_PORT ClientPort,
_In_opt_ PVOID ServerPortCookie,
_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
_In_ ULONG SizeOfContext,
_Outptr_result_maybenull_ PVOID *ConnectionCookie
)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie = NULL);

	FLT_ASSERT(clientPort == NULL);
	FLT_ASSERT(userProcess == NULL);

	//
	//  Set the user process and port. In a production filter it may
	//  be necessary to synchronize access to such fields with port
	//  lifetime. For instance, while filter manager will synchronize
	//  FltCloseClientPort with FltSendMessage's reading of the port 
	//  handle, synchronizing access to the UserProcess would be up to
	//  the filter.
	//

	userProcess = PsGetCurrentProcess();
	clientPort = ClientPort;

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("ClientHandlerPortDisconnect!ClientHandlerPortConnect: connected, port=0x%p\n", ClientPort));

	return STATUS_SUCCESS;
}


VOID
ClientHandlerPortDisconnect(
_In_opt_ PVOID ConnectionCookie
)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FileSystemDriver!ClientHandlerPortDisconnect: disconnected, port=0x%p\n", clientPort));

	//
	//  Close our handle to the connection: note, since we limited max connections to 1,
	//  another connect will not be allowed until we return from the disconnect routine.
	//

	FltCloseClientPort(gFilterHandle, &clientPort);

	//
	//  Reset the user-process field.
	//

	userProcess = NULL;
}


NTSTATUS
ClientHandlerPortMessage(
_In_ PVOID PortCookie,
_In_opt_ PVOID InputBuffer,
_In_ ULONG InputBufferLength,
_Out_opt_ PVOID OutputBuffer,
_Out_ ULONG OutputBufferLength,
_Out_ PULONG ReturnOutputBufferLength
) {
	UNREFERENCED_PARAMETER(PortCookie);
	UNREFERENCED_PARAMETER(InputBuffer);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FileSystemDriver!ClientHandlerPortMessage: Entered\n"));

	PT_DBG_PRINT(PTDBG_INFORMATION,
		("Message: %s\n", (char *)InputBuffer));
	
	if (OutputBuffer != NULL && OutputBufferLength >= InputBufferLength) {
		PT_DBG_PRINT(PTDBG_INFORMATION, ("buf: %p len: %d\n", OutputBuffer, OutputBufferLength));
		memcpy(OutputBuffer, InputBuffer, InputBufferLength);
		*ReturnOutputBufferLength = InputBufferLength;

	}


	return STATUS_SUCCESS;
}
