#ifndef _FILE_SYSTEM_DRIVER_H
#define _FILE_SYSTEM_DRIVER_H

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;

// Global data
PFLT_PORT serverPort;
PEPROCESS userProcess;
PFLT_PORT clientPort;

#define MAX_BUFFER_SIZE 2048

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
#define PTDBG_INFORMATION               0x00000004
#define PTDBG_WARNING                   0x00000008
#define PTDBG_ERROR                     0x00000010


// show all dbg message except PTDBG_TRACE_ROUTINES
ULONG gTraceFlags =
PTDBG_TRACE_OPERATION_STATUS |
PTDBG_INFORMATION |
PTDBG_WARNING |
PTDBG_ERROR;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
Prototypes
*************************************************************************/

VOID
ClientHandlerPortDisconnect(
_In_opt_ PVOID ConnectionCookie
);

NTSTATUS
ClientHandlerPortConnect(
_In_ PFLT_PORT ClientPort,
_In_opt_ PVOID ServerPortCookie,
_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
_In_ ULONG SizeOfContext,
_Outptr_result_maybenull_ PVOID *ConnectionCookie
);

NTSTATUS
ClientHandlerPortMessage(
_In_ PVOID PortCookie,
_In_ PVOID InputBuffer OPTIONAL,
_In_ ULONG InputBufferLength,
_Out_ PVOID OutputBuffer OPTIONAL,
_Out_ ULONG OutputBufferLength,
_Out_ PULONG ReturnOutputBufferLength
);

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
_In_ PDRIVER_OBJECT DriverObject,
_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
FileSystemDriverInstanceSetup(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
_In_ DEVICE_TYPE VolumeDeviceType,
_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);


NTSTATUS
FileSystemDriverUnload(
_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
FileSystemDriverInstanceQueryTeardown(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FileSystemDriverReadPreOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverReadPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FileSystemDriverWritePreOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverWritePostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FileSystemDriverCreatePreOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverCreatePostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

BOOLEAN CheckExtension(_In_ PFILE_OBJECT fileObject);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FileSystemDriverUnload)
#pragma alloc_text(PAGE, FileSystemDriverInstanceQueryTeardown)
#pragma alloc_text(PAGE, FileSystemDriverInstanceSetup)
#endif


//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	/* temporary disable create callback
	{ IRP_MJ_CREATE,
	0,
	FileSystemDriverCreatePreOperation,
	FileSystemDriverCreatePostOperation },
	*/

	{ IRP_MJ_READ,
	0,
	FileSystemDriverReadPreOperation,
	FileSystemDriverReadPostOperation },

	{ IRP_MJ_WRITE,
	0,
	FileSystemDriverWritePreOperation,
	FileSystemDriverWritePostOperation },

	{ IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks

	FileSystemDriverUnload,                           //  MiniFilterUnload

	FileSystemDriverInstanceSetup,                    //  InstanceSetup
	FileSystemDriverInstanceQueryTeardown,            //  InstanceQueryTeardown

	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};

#endif