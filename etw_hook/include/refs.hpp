#pragma once

#include <fltKernel.h>
#include <ntimage.h>
#include <intrin.h>
#include <kstl/klog.hpp>

//Allocate kernel memory without warning. You can replace ExAlloatePoolWithTag
template<typename T>
static inline T* kalloc(POOL_TYPE poolType, ULONG tag, SIZE_T size = 0)
{
	if (!size)
	{
		size = sizeof(T);
	}

	return reinterpret_cast<T*>(ExAllocatePoolWithTag(poolType, size, tag));
}

#define MAXIMUM_FILENAME_LENGTH 256

typedef struct _SYSTEM_MODULE_ENTRY
{
	ULONGLONG Unknown1;
	ULONGLONG Unknown2;
	PVOID BaseAddress;
	ULONG Size;
	ULONG Flags;
	ULONG EntryIndex;
	USHORT NameLength;  // Length of module name not including the path, this field contains valid value only for NTOSKRNL module
	USHORT PathLength;  // Length of 'directory path' part of modulename
	CHAR Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	ULONG Unknown1;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemModuleInformation = 0xb,
	SystemKernelDebuggerInformation = 0x23,
	SystemFirmwareTableInformation = 0x4c
} SYSTEM_INFORMATION_CLASS;

extern "C"
{
	NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);

	NTKERNELAPI NTSTATUS NTAPI NtQuerySystemInformation(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	NTKERNELAPI PVOID RtlPcToFileHeader(PVOID pc, PVOID* base);
};
