/*************************************************************************
MiniFilter callback routines.
*************************************************************************/


#include "FileSystemDriver.h"


FLT_PREOP_CALLBACK_STATUS
FileSystemDriverPreOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FileSystemDriver!FileSystemDriverPreOperation: Entered\n"));

	PEPROCESS proc = IoThreadToProcess(Data->Thread);
	HANDLE pid = PsGetProcessId(proc);
	PT_DBG_PRINT(PTDBG_INFORMATION, ("Process PID is: %d\n", pid));

	PCTX_INSTANCE_CONTEXT instanceContext;

	NTSTATUS status = FltGetInstanceContext(FltObjects->Instance, &instanceContext);
	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverPreOperation: Fails on FltGetInstanceContext. Status=%08x\n", status));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	PT_DBG_PRINT(PTDBG_INFORMATION, ("Reading file from volume with name: %wZ\n", instanceContext->VolumeName));

	// get file info and send it to user-mode application

	PFLT_FILE_NAME_INFORMATION fileInformation = NULL;
	MESSAGE_BODY_STRUCT message;

	if ((clientPort != NULL) && (((DWORD)pid == targetPid) || (targetPid == -1)) && (pid != userProcessId)) {
		try {
			if (FltObjects->FileObject != NULL) {
				status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fileInformation);
				if (!NT_SUCCESS(status)) {
					PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS, ("FileSystemDriver!FileSystemDriverPreOperation: Fails on FltGetFileNameInformation, status=%08x\n", status));
					leave;
				}
				
				message.messageType.operationStatus.ioOpType = Data->Iopb->MajorFunction;
				message.messageType.operationStatus.pid = (DWORD)pid;
				
				RtlCopyMemory(message.messageType.operationStatus.guid,
							  instanceContext->VolumeName.Buffer,
							  instanceContext->VolumeName.Length);
				
				message.messageType.operationStatus.guid[instanceContext->VolumeName.Length / sizeof(WCHAR)] = L'\0';
				
				RtlCopyMemory(message.messageType.operationStatus.path,
							  fileInformation->Name.Buffer + (fileInformation->Volume.Length / sizeof(WCHAR) + 1),
							  fileInformation->Name.Length - fileInformation->Volume.Length - 1);
				
				message.messageType.operationStatus.path[(fileInformation->Name.Length - fileInformation->Volume.Length - 1) / sizeof(WCHAR)] = L'\0';
				
				status = FltSendMessage(gFilterHandle, &clientPort, &message, sizeof(MESSAGE_BODY_STRUCT), NULL, NULL, NULL);
				if (!NT_SUCCESS(status)) {
					PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS, ("FileSystemDriver!FileSystemDriverPreOperation: Fails on FltSendMessage, status=%08x\n", status));
					leave;
				}
			}
		} finally {
			if (fileInformation != NULL)
				FltReleaseFileNameInformation(fileInformation);
		}
	}

	FltReleaseContext(instanceContext);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

