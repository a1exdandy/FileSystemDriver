/*++

Module Name:

    FileSystemDriver.c

Abstract:

    This is the main module of the FileSystemDriver miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;

// Global data
PFLT_PORT serverPort;
PEPROCESS userProcess;
PFLT_PORT clientPort;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
#define PTDBG_INFORMATION               0x00000004
#define PTDBG_WARNING                   0x00000008
#define PTDBG_ERROR                     0x00000010


// show all dbg message
ULONG gTraceFlags = 
	PTDBG_TRACE_OPERATION_STATUS | 
	PTDBG_TRACE_ROUTINES |
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

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
FileSystemDriverInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);


NTSTATUS
FileSystemDriverUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
FileSystemDriverInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
FileSystemDriverReadPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverReadPostOperation (
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
	 
	/* temporary disable write callback
	{ IRP_MJ_WRITE,
      0,
      FileSystemDriverWritePreOperation,
      FileSystemDriverWritePostOperation },
	 */
    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
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


NTSTATUS
FileSystemDriverInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileSystemDriver!FileSystemDriverInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
FileSystemDriverInstanceQueryTeardown (
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This is called when an instance is being manually deleted by a
call to FltDetachVolume or FilterDetach thereby giving us a
chance to fail that detach request.

If this routine is not defined in the registration structure, explicit
detach requests via FltDetachVolume or FilterDetach will always be
failed.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Indicating where this detach request came from.

Return Value:

Returns the status of this operation.

--*/
{
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Flags );

	PAGED_CODE();

	PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
		("FileSystemDriver!FileSystemDriverInstanceQueryTeardown: Entered\n") );

	return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileSystemDriver!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

	try {

		status = FltRegisterFilter(DriverObject,
			&FilterRegistration,
			&gFilterHandle);

		if (!NT_SUCCESS(status)) {
			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("FileSystemDriver!DriverEntry: FltREgisterFilter Failed, status=%08x\n",
				status));
			leave;
		}

		RtlInitUnicodeString(&uniString, L"\\FileSystemDriver");

		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
		if (!NT_SUCCESS(status)) {
			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("FileSystemDriver!DriverEntry: FltBuildDefaultSecurityDescriptor Failed, status=%08x\n",
				status));
			leave;
		}

		InitializeObjectAttributes(&oa,
			&uniString,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			sd);

		status = FltCreateCommunicationPort(gFilterHandle,
			&serverPort,
			&oa,
			NULL,
			ClientHandlerPortConnect,
			ClientHandlerPortDisconnect,
			NULL,
			1);

		//
		//  Free the security descriptor in all cases.	It is not needed once
		//  the call to FltCreateCommunicationPort() is made.
		//
		FltFreeSecurityDescriptor(sd);
		
		if (!NT_SUCCESS(status)) {
			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("FileSystemDriver!DriverEntry: ltCreateCommunicationPort Failed, status=%08x\n",
				status));
			leave;
		}

		//
		//  Start filtering i/o
		//
		status = FltStartFiltering(gFilterHandle);

		if (!NT_SUCCESS(status)) {
			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("FileSystemDriver!DriverEntry: FltStartFiltering Failed, status=%08x\n",
				status));
			leave;
		}

	} finally {

		if (!NT_SUCCESS(status)) {
			
			if (NULL != serverPort) {
				FltCloseCommunicationPort(serverPort);
			}

			if (NULL != gFilterHandle) {
				FltUnregisterFilter(gFilterHandle);
			}

		}
	}

    return status;
}

NTSTATUS
FileSystemDriverUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileSystemDriver!FileSystemDriverUnload: Entered\n") );

	FltCloseCommunicationPort( serverPort );
    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
FileSystemDriverReadPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{

	UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileSystemDriver!FileSystemDriverReadPreOperation: Entered\n") );

	if (NULL != FltObjects->FileObject) {
		PT_DBG_PRINT( PTDBG_INFORMATION,
			("Read file: %wZ\n", &FltObjects->FileObject->FileName));
	}

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverReadPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileSystemDriver!FileSystemDriverReadPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
FileSystemDriverWritePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

This routine is a pre-operation dispatch routine for this miniFilter.

This is non-pageable because it could be called on the paging path

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The context for the completion routine for this
operation.

Return Value:

The return value is the status of the operation.

--*/
{

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FileSystemDriver!FileSystemDriverWritePreOperation: Entered\n"));

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverWritePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

This routine is the post-operation completion routine for this
miniFilter.

This is non-pageable because it may be called at DPC level.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The completion context set in the pre-operation routine.

Flags - Denotes whether the completion is successful or is being drained.

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FileSystemDriver!FileSystemDriverWritePostOperation: Entered\n"));

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
FileSystemDriverCreatePreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

This routine is a pre-operation dispatch routine for this miniFilter.

This is non-pageable because it could be called on the paging path

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The context for the completion routine for this
operation.

Return Value:

The return value is the status of the operation.

--*/
{

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FileSystemDriver!FileSystemDriverCreatePreOperation: Entered\n"));

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverCreatePostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

This routine is the post-operation completion routine for this
miniFilter.

This is non-pageable because it may be called at DPC level.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The completion context set in the pre-operation routine.

Flags - Denotes whether the completion is successful or is being drained.

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("FileSystemDriver!FileSystemDriverCreatePostOperation: Entered\n"));

	return FLT_POSTOP_FINISHED_PROCESSING;
}



NTSTATUS
ClientHandlerPortConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID *ConnectionCookie
)
/*++

Routine Description

This is called when user-mode connects to the server port - to establish a
connection

Arguments

ClientPort - This is the client connection port that will be used to
send messages from the filter

ServerPortCookie - The context associated with this port when the
minifilter created this port.

ConnectionContext - Context from entity connecting to this port (most likely
your user mode service)

SizeofContext - Size of ConnectionContext in bytes

ConnectionCookie - Context to be passed to the port disconnect routine.

Return Value

STATUS_SUCCESS - to accept the connection

--*/
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

	DbgPrint("ClientHandlerPortDisconnect!ClientHandlerPortConnect: connected, port=0x%p\n", ClientPort);

	return STATUS_SUCCESS;
}


VOID
ClientHandlerPortDisconnect(
	_In_opt_ PVOID ConnectionCookie
)
/*++

Routine Description

This is called when the connection is torn-down. We use it to close our
handle to the connection

Arguments

ConnectionCookie - Context from the port connect routine

Return value

None

--*/
{
	UNREFERENCED_PARAMETER(ConnectionCookie);

	PAGED_CODE();

	DbgPrint("FileSystemDriver!ClientHandlerPortDisconnect: disconnected, port=0x%p\n", clientPort);

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
