#pragma warning(disable : 5040)

#include <refs.hpp>
#include <etwhook_init.hpp>
#include <etwhook_manager.hpp>

#define POOL_TAG 'TSET'

NTSTATUS detour_NtCreateFile(
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
			RtlZeroMemory(name, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			RtlCopyMemory(name, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);

			if (wcsstr(name, L"oxygen.txt"))
			{
				ExFreePoolWithTag(name, POOL_TAG);
				return STATUS_ACCESS_DENIED;
			}

			ExFreePoolWithTag(name, POOL_TAG);
		}
	}


	return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
		IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		CreateDisposition, CreateOptions, EaBuffer, EaLength);
}


NTSTATUS detour_NtClose(HANDLE h)
{
	//LOG_INFO("ZwClose caught\r\n");
	return NtClose(h);
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING)
{
	auto status = STATUS_SUCCESS;

	driverObject->DriverUnload = [](PDRIVER_OBJECT)
	{
		EtwHookManager::GetInstance()->Destory();
	};

	kstd::Logger::Initialize("etw_hook");

	LOG_INFO("init...\r\n");


	status = EtwHookManager::GetInstance()->Initialize();

	EtwHookManager::GetInstance()->add_hook(NtCreateFile, detour_NtCreateFile);
	EtwHookManager::GetInstance()->add_hook(NtClose, detour_NtClose);

	return status;
}
