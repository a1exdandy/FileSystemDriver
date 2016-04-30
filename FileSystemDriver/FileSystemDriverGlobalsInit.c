#include "FileSystemDriver.h"

// show all dbg message except PTDBG_TRACE_ROUTINES
ULONG gTraceFlags =
	PTDBG_TRACE_OPERATION_STATUS |
	PTDBG_INFORMATION |
	PTDBG_WARNING |
	PTDBG_ERROR;

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),           //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	ContextRegistration,                //  Context
	Callbacks,                          //  Operation callbacks
	FileSystemDriverUnload,             //  MiniFilterUnload
	FileSystemDriverInstanceSetup,      //  InstanceSetup
	NULL,								//  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	CtxInstanceTeardownComplete,        //  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_INSTANCE_CONTEXT,
	0,
	CtxContextCleanup,
	CTX_INSTANCE_CONTEXT_SIZE,
	CTX_OBJECT_TAG },

	{ FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	{ IRP_MJ_CREATE,
	0,
	FileSystemDriverPreOperation,
	FileSystemDriverPostOperation },

	{ IRP_MJ_READ,
	0,
	FileSystemDriverPreOperation,
	FileSystemDriverPostOperation },

	{ IRP_MJ_WRITE,
	0,
	FileSystemDriverPreOperation,
	FileSystemDriverPostOperation },

	{ IRP_MJ_OPERATION_END }
};
