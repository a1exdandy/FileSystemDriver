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
ULONG_PTR OperationStatusCtx = 1;

// Global data
PFLT_PORT serverPort;
PEPROCESS userProcess;
PFLT_PORT clientPort;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 3; // show all dbg message


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

VOID
FileSystemDriverInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
FileSystemDriverInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
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
FileSystemDriverPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
FileSystemDriverOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
FileSystemDriverPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
FileSystemDriverDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FileSystemDriverUnload)
#pragma alloc_text(PAGE, FileSystemDriverInstanceQueryTeardown)
#pragma alloc_text(PAGE, FileSystemDriverInstanceSetup)
#pragma alloc_text(PAGE, FileSystemDriverInstanceTeardownStart)
#pragma alloc_text(PAGE, FileSystemDriverInstanceTeardownComplete)
#endif


//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

#if 1 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

	/*{ IRP_MJ_CREATE_NAMED_PIPE,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_CLOSE,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },*/

    { IRP_MJ_READ,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },
	 
	{ IRP_MJ_WRITE,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

   /*{ IRP_MJ_QUERY_INFORMATION,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_SET_EA,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      FileSystemDriverPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_PNP,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      FileSystemDriverPreOperation,
      FileSystemDriverPostOperation },*/

#endif // TODO

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
    FileSystemDriverInstanceTeardownStart,            //  InstanceTeardownStart
    FileSystemDriverInstanceTeardownComplete,         //  InstanceTeardownComplete

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


VOID
FileSystemDriverInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileSystemDriver!FileSystemDriverInstanceTeardownStart: Entered\n") );
}


VOID
FileSystemDriverInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileSystemDriver!FileSystemDriverInstanceTeardownComplete: Entered\n") );
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
    NTSTATUS status;
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

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

	RtlInitUnicodeString(&uniString, L"\\FileSystemDriver");

	if (NT_SUCCESS(status)) {
		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	}

	if (NT_SUCCESS(status)) {

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
	}
	
	
    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //
        status = FltStartFiltering( gFilterHandle );
        if (!NT_SUCCESS( status )) {
			FltCloseCommunicationPort(serverPort);
            FltUnregisterFilter( gFilterHandle );
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
	FltCloseCommunicationPort(serverPort);
    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
FileSystemDriverPreOperation (
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
	//PANSI_STRING ansi_str = NULL;
	NTSTATUS status;


	UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileSystemDriver!FileSystemDriverPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

	
	if (FileSystemDriverDoRequestOperationStatus(Data)) {

		status = FltRequestOperationStatusCallback(Data,
			FileSystemDriverOperationStatusCallback,
			(PVOID)(++OperationStatusCtx));
		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("FileSystemDriver!FileSystemDriverPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
				status));
		}
	}
	if (FltObjects->FileObject != NULL) {
		//RtlUnicodeStringToAnsiString(ansi_str, &FltObjects->FileObject->FileName, TRUE);
		DbgPrint("File name: %wZ", &FltObjects->FileObject->FileName);
		//RtlFreeAnsiString(ansi_str);
	}

	
    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
FileSystemDriverOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileSystemDriver!FileSystemDriverOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("FileSystemDriver!FileSystemDriverOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
FileSystemDriverPostOperation (
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
                  ("FileSystemDriver!FileSystemDriverPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
FileSystemDriverPreOperationNoPostOperation (
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
                  ("FileSystemDriver!FileSystemDriverPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
FileSystemDriverDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
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
