#pragma warning(disable : 5040)

#include <refs.hpp>
#include <etwhook_utils.hpp>

#define POOL_TAG 'UWTE'

static NTSTATUS w2s(const wchar_t* src, char* dest, size_t destSize)
{
	if (!src || !dest || destSize == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	size_t i = 0;
	while (src[i] != L'\0' && i < destSize - 1)
	{
		if (src[i] <= 0x7F)
		{
			dest[i] = static_cast<char>(src[i]);
		}
		else
		{
			dest[i] = '?';
		}
		++i;
	}

	dest[i] = '\0';
	return STATUS_SUCCESS;
}

void* FindModuleBase(const wchar_t* moduleName, ULONG* size)
{
	ULONG needSize = 0;
	ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needSize);
	void* findBase = 0;
	char moduleNameAscii[256] = {};

	w2s(moduleName, moduleNameAscii, sizeof(moduleNameAscii));

	auto info = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>(ExAllocatePoolWithTag(NonPagedPool, needSize, POOL_TAG));

	if (!info)
	{
		return nullptr;
	}

	do
	{

		if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, info, needSize, &needSize)))
		{
			break;
		}

		for (size_t i = 0; i < info->Count; ++i)
		{
			SYSTEM_MODULE_ENTRY* moduleEntry = &info->Module[i];
			char* lastSlash = strrchr(moduleEntry->Name, '\\');
			if (lastSlash)
			{
				lastSlash++; // Skip the slash
			}
			else
			{
				lastSlash = moduleEntry->Name;
			}

			if (!_strnicmp(lastSlash, moduleNameAscii, strlen(moduleNameAscii)))
			{
				findBase = moduleEntry->BaseAddress;
				if (size)
					*size = moduleEntry->Size;
				break;
			}
		}

	} while (false);

	if (info)
		ExFreePoolWithTag(info, POOL_TAG);

	return findBase;
}
