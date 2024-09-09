#pragma warning(disable : 5040)

#include <etwhook_init.hpp>
#include <etwhook_manager.hpp>

#define POOL_TAG 'TSET'

NTSTATUS DetourNtCreateFile(
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
				EtwHookManager::GetInstance()->NotifyHookProcessed();
				return STATUS_ACCESS_DENIED;
			}

			ExFreePoolWithTag(name, POOL_TAG);
		}
	}


	NTSTATUS status = NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
		IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		CreateDisposition, CreateOptions, EaBuffer, EaLength);
	
	EtwHookManager::GetInstance()->NotifyHookProcessed();

	return status;
}


NTSTATUS DetourNtClose(HANDLE h)
{
	//LOG_INFO("ZwClose caught\n");
	NTSTATUS status = NtClose(h);

	EtwHookManager::GetInstance()->NotifyHookProcessed();

	return status;
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING)
{
	driverObject->DriverUnload = [](PDRIVER_OBJECT)
	{
		EtwHookManager* manager = EtwHookManager::GetInstance();
		if (manager)
			manager->Destory();
	};

	kstd::Logger::Initialize("etw_hook");

	LOG_INFO("init...");

	EtwHookManager* manager = EtwHookManager::GetInstance();

	if (manager)
	{
		NTSTATUS status = manager->Initialize();

		if (NT_SUCCESS(status))
		{
			manager->AddHook(NtCreateFile, DetourNtCreateFile);
			manager->AddHook(NtClose, DetourNtClose);
		}
	}

	return STATUS_SUCCESS;
}
