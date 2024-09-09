#pragma warning(disable : 5040)

#include <etwhook_init.hpp>
#include <etwhook_manager.hpp>

#define _countof(arr) (sizeof(arr) / sizeof(arr[0]))

#define POOL_TAG 'TSET'

static volatile LONG gHooksActive = 0;

static volatile LONG gCallStats[0x0200] = {0};

static volatile bool gIsUnloading = false;

static void* gStatsThread = nullptr;

static NTSTATUS DetourNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength)
{

	if (ObjectAttributes &&
		ObjectAttributes->ObjectName &&
		ObjectAttributes->ObjectName->Buffer)
	{
		wchar_t* name = reinterpret_cast<wchar_t*>
			(ExAllocatePoolWithTag(NonPagedPool, ObjectAttributes->ObjectName->Length + sizeof(wchar_t), POOL_TAG));

		if (name)
		{
			RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
			name[ObjectAttributes->ObjectName->Length / sizeof(wchar_t)] = 0;

			if (wcsstr(name, L"oxygen.txt"))
			{
				ExFreePoolWithTag(name, POOL_TAG);
				InterlockedDecrement(&gHooksActive);
				return STATUS_ACCESS_DENIED;
			}

			ExFreePoolWithTag(name, POOL_TAG);
		}
	}


	NTSTATUS status = NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
		IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		CreateDisposition, CreateOptions, EaBuffer, EaLength);
	
	InterlockedDecrement(&gHooksActive);

	return status;
}


static NTSTATUS DetourNtClose(HANDLE h)
{
	//LOG_INFO("ZwClose caught\n");
	NTSTATUS status = NtClose(h);

	InterlockedDecrement(&gHooksActive);

	return status;
}

static void __fastcall TestHookCallback(_In_ unsigned int systemCallIndex, _Inout_ void** systemCallFunction)
{
	UNREFERENCED_PARAMETER(systemCallIndex);

	// We can overwrite the return address on the stack to our detours

	InterlockedIncrement(gCallStats + systemCallIndex);

	if (*systemCallFunction == NtCreateFile)
	{
		InterlockedIncrement(&gHooksActive);
		*systemCallFunction = DetourNtCreateFile;
	}
	else if (*systemCallFunction == NtClose)
	{
		InterlockedIncrement(&gHooksActive);
		*systemCallFunction = DetourNtClose;
	}
}

static void StatsThreadRoutine(void* context)
{
	UNREFERENCED_PARAMETER(context);

	for (int i = 0; !gIsUnloading; ++i)
	{
		if (!(i % 10)) // Once in 10 seconds
		{
			for (int j = 0; j < _countof(gCallStats); ++j)
			{
				if (gCallStats[j])
				{
					LOG_INFO("STATS: %d (0x%x) -> %d", j, j, gCallStats[j]);
				}
			}
		}

		LARGE_INTEGER delayTime = {};
		delayTime.QuadPart = -10 * 1000000;//1 second
		KeDelayExecutionThread(KernelMode, false, &delayTime);
	}
}

static void DriverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);

	gIsUnloading = true;

	EtwHookManager* manager = EtwHookManager::GetInstance();
	if (manager)
		manager->Destory();

	while (gHooksActive)
	{
		LOG_INFO("Hooks active: %d", gHooksActive);
		// Wait for syscalls to complete
		// WARNING! This is not safe, some syscalls (at least NtContinue) might still be active!
		LARGE_INTEGER delayTime = {};
		delayTime.QuadPart = -10 * 1000000 * 2;//2 seconds
		KeDelayExecutionThread(KernelMode, false, &delayTime);
	}

	KeWaitForSingleObject(gStatsThread, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject(gStatsThread);

	LOG_INFO("Unloaded");
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING)
{
	driverObject->DriverUnload = DriverUnload;

	kstd::Logger::Initialize("etw_hook");

	LOG_INFO("Started");

	EtwHookManager* manager = EtwHookManager::GetInstance();

	if (manager)
	{
		manager->Initialize(TestHookCallback);
	}

	HANDLE statsThreadHandle = nullptr;
	OBJECT_ATTRIBUTES objectAttributes = {0};

	InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS status = PsCreateSystemThread(&statsThreadHandle, THREAD_ALL_ACCESS, &objectAttributes, NtCurrentProcess(), NULL, StatsThreadRoutine, NULL);
	if (NT_SUCCESS(status))
	{
		status = ObReferenceObjectByHandle(statsThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &gStatsThread, NULL);
		ZwClose(statsThreadHandle);
	}

	return STATUS_SUCCESS;
}
