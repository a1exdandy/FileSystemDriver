#include "FileSystemDriver.h"

NTSTATUS FileSystemDriverInstanceSetup (_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();
	
    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverInstanceSetup: Entered\n") );
	
	if (NULL == FltObjects->Volume)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverInstanceSetup: Volume is NULL\n"));
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	ULONG needed = 0;
	NTSTATUS status = FltGetVolumeGuidName(FltObjects->Volume, NULL, &needed);
	if (STATUS_BUFFER_TOO_SMALL != status)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverInstanceSetup: Error on first call FltGetVolumeGuidName Status=%08x\n", status));
		return STATUS_FLT_DO_NOT_ATTACH;
	}
	
	PCTX_INSTANCE_CONTEXT instanceContext = NULL;
	status = FltAllocateContext(FltObjects->Filter, FLT_INSTANCE_CONTEXT, CTX_INSTANCE_CONTEXT_SIZE, NonPagedPool,	&instanceContext);
	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverInstanceSetup: Can't allocate context! Status=%08x\n", status));
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	instanceContext->VolumeName.Length = 0;
	instanceContext->Instance = FltObjects->Instance;
	instanceContext->Volume = FltObjects->Volume;
	instanceContext->VolumeName.MaximumLength = (USHORT) needed;
	
	instanceContext->VolumeName.Buffer = ExAllocatePoolWithTag(PagedPool, instanceContext->VolumeName.MaximumLength, CTX_STRING_TAG);
	if (NULL == instanceContext->VolumeName.Buffer)
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverInstanceSetup: Error on memory allocation!\n"));
		FltReleaseContext(instanceContext);
		return STATUS_FLT_DO_NOT_ATTACH;
	}
	
	status = FltGetVolumeGuidName(FltObjects->Volume, &instanceContext->VolumeName, &needed);
	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverInstanceSetup: Can't get volume name! Status=%08x\n", status));
		FltReleaseContext(instanceContext);
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	PT_DBG_PRINT(PTDBG_INFORMATION, ("Volume name: %wZ\n", instanceContext->VolumeName));

	status = FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, instanceContext, NULL);
	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverInstanceSetup: Can't set instance context! Status=%08x\n", status));
		FltReleaseContext(instanceContext);
		return STATUS_FLT_DO_NOT_ATTACH;
	}
	
	FltReleaseContext(instanceContext);
	
    return STATUS_SUCCESS;
}

VOID CtxInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	PCTX_INSTANCE_CONTEXT instanceContext;

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverInstanceTeardownComplete: Entered\n"));

	NTSTATUS status = FltGetInstanceContext(FltObjects->Instance, &instanceContext);
	if (!NT_SUCCESS(status))
	{
		PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverInstanceQueryTeardown: Fails on FltGetInstanceContext. Status=%08x\n", status));
		return;
	}

	PT_DBG_PRINT(PTDBG_INFORMATION, ("Unregistering context with volume name: %wZ\n", instanceContext->VolumeName));

	FltReleaseContext(instanceContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverInstanceTeardownComplete: Completed!\n"));
}

VOID CtxContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType)
{
	PAGED_CODE();

	switch (ContextType) {
	case FLT_INSTANCE_CONTEXT:
		ExFreePoolWithTag(((PCTX_INSTANCE_CONTEXT)Context)->VolumeName.Buffer, CTX_STRING_TAG);
		break;
	}
}

/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS DriverEntry (_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	targetPid = (DWORD) -1;

    UNREFERENCED_PARAMETER(RegistryPath);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!DriverEntry: Entered\n"));

	try
	{
		status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
		if (!NT_SUCCESS(status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS, ("FileSystemDriver!DriverEntry: FltREgisterFilter Failed, status=%08x\n", status));
			leave;
		}

		RtlInitUnicodeString(&uniString, L"\\FileSystemDriver");

		status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
		if (!NT_SUCCESS(status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS, ("FileSystemDriver!DriverEntry: FltBuildDefaultSecurityDescriptor Failed, status=%08x\n", status));
			leave;
		}

		InitializeObjectAttributes(&oa, &uniString,	OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,	sd);

		status = FltCreateCommunicationPort(gFilterHandle, &serverPort, &oa, NULL, ClientHandlerPortConnect, ClientHandlerPortDisconnect, ClientHandlerPortMessage,	1);
		
		FltFreeSecurityDescriptor(sd);
		if (!NT_SUCCESS(status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS, ("FileSystemDriver!DriverEntry: ltCreateCommunicationPort Failed, status=%08x\n", status));
			leave;
		}

		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status))
		{
			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS, ("FileSystemDriver!DriverEntry: FltStartFiltering Failed, status=%08x\n", status));
			leave;
		}

	} finally
	{
		if (!NT_SUCCESS(status))
		{
			if (NULL != serverPort)
				FltCloseCommunicationPort(serverPort);

			if (NULL != gFilterHandle)
				FltUnregisterFilter(gFilterHandle);
		}
	}

    return status;
}

NTSTATUS FileSystemDriverUnload (_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverUnload: Entered\n"));

	FltCloseCommunicationPort(serverPort);
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverUnload: Communication port closed\n"));

    FltUnregisterFilter(gFilterHandle);
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("FileSystemDriver!FileSystemDriverUnload: FilterUnregistered\n"));

    return STATUS_SUCCESS;
}
