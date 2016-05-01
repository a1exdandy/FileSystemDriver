#ifndef _FILE_SYSTEM_DRIVER_H
#define _FILE_SYSTEM_DRIVER_H

#ifndef CLIENT_SIDE
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <windef.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;

// Global data
PFLT_PORT serverPort;
PEPROCESS userProcess;
PFLT_PORT clientPort;

//tags
#define CTX_STRING_TAG 'CTXt'
#define CTX_OBJECT_TAG 'CTXo'

#define MAX_BUFFER_SIZE 2048

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
#define PTDBG_INFORMATION               0x00000004
#define PTDBG_WARNING                   0x00000008
#define PTDBG_ERROR                     0x00000010


extern ULONG gTraceFlags;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

typedef struct _CTX_INSTANCE_CONTEXT {
	PFLT_INSTANCE Instance;
	PFLT_VOLUME Volume;
	UNICODE_STRING VolumeName;
} CTX_INSTANCE_CONTEXT, *PCTX_INSTANCE_CONTEXT;


#define CTX_INSTANCE_CONTEXT_SIZE         sizeof( CTX_INSTANCE_CONTEXT )
/*************************************************************************
Prototypes
*************************************************************************/

void
FileClearCache(
PFILE_OBJECT pFileObject
);

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
_In_opt_ PVOID InputBuffer,
_In_ ULONG InputBufferLength,
_Out_opt_ PVOID OutputBuffer,
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

VOID CtxInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

NTSTATUS
FileSystemDriverInstanceQueryTeardown(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FileSystemDriverPreOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

VOID CtxContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType);

BOOLEAN CheckExtension(_In_ PFILE_OBJECT fileObject);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FileSystemDriverUnload)
#pragma alloc_text(PAGE, CtxInstanceTeardownComplete)
#pragma alloc_text(PAGE, FileSystemDriverInstanceSetup)
#pragma alloc_text(PAGE, CtxContextCleanup)
#endif

extern CONST FLT_OPERATION_REGISTRATION Callbacks[];
extern CONST FLT_REGISTRATION FilterRegistration;
extern const FLT_CONTEXT_REGISTRATION ContextRegistration[];

#endif

#ifdef CLIENT_SIDE
#define RTL_GUID_STRING_SIZE 38
#endif

// shared message structs
enum OPERATION_TYPE {
	ReadOp, WriteOp
};

typedef struct _MESSAGE_BODY_STRUCT {
	UINT8 ioOpType;
	// + size of prefix "\??\Volume"
	WCHAR guid[64];
	WCHAR path[512];

} MESSAGE_BODY_STRUCT, *PMESSAGE_BODY_STRUCT;

typedef struct _MESSAGE_STRUCT {
	FILTER_MESSAGE_HEADER header;
	MESSAGE_BODY_STRUCT body;
} MESSAGE_STRUCT, *PMESSAGE_STRUCT;

#endif