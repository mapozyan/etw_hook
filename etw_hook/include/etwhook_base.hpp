#pragma once

#include <refs.hpp>

#define ETW_BASE_POOL_TAG 'BWTE'

template <POOL_TYPE poolType>
class _EtwBase
{
public:
	void* operator new(size_t size)
	{
		return kalloc<char>(poolType, ETW_BASE_POOL_TAG, size);
	}
	void  operator delete(void* p, size_t size)
	{
		UNREFERENCED_PARAMETER(size);
		return ExFreePoolWithTag(p, ETW_BASE_POOL_TAG);
	}
};

using EtwBase = _EtwBase<NonPagedPool>;
