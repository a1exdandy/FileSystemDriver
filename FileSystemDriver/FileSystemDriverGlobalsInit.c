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
