/*++

Module Name:

    FileSystemDriver.c

Abstract:

    This is the main module of the FileSystemDriver miniFilter driver.

Environment:

    Kernel mode

--*/

#include "FileSystemDriver.h"

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
	/*NTSTATUS status;*/

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FileSystemDriver!FileSystemDriverInstanceSetup: Entered\n") );
	/*
	if (NULL != FltObjects->Volume) {
		WCHAR buffer[MAX_BUFFER_SIZE];
		UNICODE_STRING volumeName;
		RtlInitEmptyUnicodeString(&volumeName, buffer, MAX_BUFFER_SIZE);
		status = FltGetVolumeName(FltObjects->Volume, NULL, NULL);
		if (NT_SUCCESS(status)) {
			PT_DBG_PRINT(PTDBG_INFORMATION,
				("Volume name: %wZ\n", volumeName));
		} else {
			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("FileSystemDriver!DriverEntry: FltGetVolumeName Failed, status=%08x\n", status));
		}
	} else {
		PT_DBG_PRINT(PTDBG_WARNING,
			("FltObjects->Volume is NULL\n"));
	}
	*/

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
			ClientHandlerPortMessage,
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
