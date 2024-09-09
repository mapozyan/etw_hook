#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>
#include <ntimage.h>

namespace kstd
{
	static const DWORD X64 = 0x8664;

	static void* PatternFind(void* addr, size_t size, const char* pattern, const char* mask);

	static void* PatternFindSections(void* base, const char* pattern, const char* mask, const char* name);

	static bool IsValidX64PE(char* base);

	static bool PatternCheck(const char* data, const char* pattern, const char* mask);

	inline void* PatternFind(void* addr, size_t size, const char* pattern, const char* mask)
	{
		size -= strlen(mask);

		for (size_t i = 0; i < size; ++i)
		{
			char* p = reinterpret_cast<char*>(addr) + i;
			if (PatternCheck(p, pattern, mask))
				return reinterpret_cast<void*>(p);
		}

		return 0;
	}

	static inline void* PatternFindSections(void* base, const char* pattern, const char* mask, const char* name)
	{
		PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		PIMAGE_NT_HEADERS64 ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<char*>(base) + dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
		for (unsigned short i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
		{
			PIMAGE_SECTION_HEADER p = section + i;

			if (strstr(reinterpret_cast<const char*>(p->Name), name))
			{
				void* result = PatternFind(reinterpret_cast<char*>(base) + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
				if (result)
					return result;
			}
		}

		return 0;
	}

	static inline bool PatternCheck(const char* data, const char* pattern, const char* mask)
	{
		size_t len = strlen(mask);

		for (size_t i = 0; i < len; ++i)
		{
			if (data[i] == pattern[i] || mask[i] == '?')
				continue;
			else
				return false;
		}

		return true;
	}

	static inline bool IsValidX64PE(char* base)
	{
		if (!MmIsAddressValid(base)) return false;

		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return false;

		auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>((UINT_PTR)base + dos_header->e_lfanew);
		if (nt_headers->FileHeader.Machine != X64) return false;

		return true;
	}

} // namespace kstd
