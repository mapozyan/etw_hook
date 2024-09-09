#pragma once

#define RTL_USE_AVL_TABLES 0
#include <fltKernel.h>

namespace kstd
{

	template<typename T>
	class kavl {
	private:
		static const unsigned POOL_TAG = 'LVAK';

		static PVOID AvlAlloc(RTL_AVL_TABLE* table, CLONG size);
		static VOID AvlFree(RTL_AVL_TABLE* table, PVOID buf);
		static RTL_GENERIC_COMPARE_RESULTS AvlCompare(RTL_AVL_TABLE* table, PVOID first, PVOID second);
	
	public:
		bool Initialize();
		bool Destory();

		bool Insert(T&& item);

		T* Find(const T& item);
		void Remove(T* item);

		ULONG Size();

		kavl() = default;
		~kavl() = default;
		kavl(const T& rhs) = delete;
		kavl(T&& rhs) = delete;
		kavl& operator=(const T& rhs) = delete;
		kavl& operator=(T&& rhs) = delete;

	private:
		T&& move(T& v) const { return static_cast<T&&>(v); }

		PERESOURCE _lock;
		PRTL_AVL_TABLE _table;
	};


	template<typename T>
	inline PVOID kavl<T>::AvlAlloc(RTL_AVL_TABLE* table, CLONG size)
	{
		UNREFERENCED_PARAMETER(table);

		return ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);
	}


	template<typename T>
	inline VOID kavl<T>::AvlFree(RTL_AVL_TABLE* table, PVOID buf)
	{
		UNREFERENCED_PARAMETER(table);

		return ExFreePoolWithTag(buf, POOL_TAG);
	}


	template<typename T>
	inline RTL_GENERIC_COMPARE_RESULTS kavl<T>::AvlCompare(RTL_AVL_TABLE* table, PVOID first, PVOID second)
	{
		UNREFERENCED_PARAMETER(table);

		if (*reinterpret_cast<T*>(first) == *reinterpret_cast<T*>(second))
			return GenericEqual;
		else
		{
			if (*reinterpret_cast<T*>(first) < *reinterpret_cast<T*>(second))
				return GenericLessThan;
			else
				return GenericGreaterThan;
		}
	}


	template<typename T>
	inline bool kavl<T>::Initialize()
	{

		_lock = reinterpret_cast<PERESOURCE>(ExAllocatePoolWithTag(NonPagedPool, sizeof ERESOURCE, POOL_TAG));
		if (!_lock)
			return false;
		_table = reinterpret_cast<PRTL_AVL_TABLE>(ExAllocatePoolWithTag(NonPagedPool, sizeof RTL_AVL_TABLE, POOL_TAG));
		if (!_table)
		{
			ExFreePoolWithTag(_lock, POOL_TAG);
			return false;
		}

		RtlInitializeGenericTableAvl(_table, AvlCompare, AvlAlloc, AvlFree, nullptr);

		ExInitializeResourceLite(_lock);

		return true;
	}


	template<typename T>
	inline bool kavl<T>::Destory()
	{
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(_lock, true);

		auto cnt = RtlNumberGenericTableElementsAvl(_table);

		for (ULONG i = 0; i < cnt; i++)
		{
			auto node = RtlGetElementGenericTableAvl(_table, 0);
			if (node)
			{
				//directly call dtor
				reinterpret_cast<T*>(node)->~T();

				RtlDeleteElementGenericTableAvl(_table, node);
			}

		}
		ExReleaseResourceLite(_lock);
		KeLeaveCriticalRegion();

		ExDeleteResourceLite(_lock);
		if (_table)
		{
			ExFreePoolWithTag(_table, POOL_TAG);
			_table = nullptr;
		}
		if (_lock)
		{
			ExFreePoolWithTag(_lock, POOL_TAG);
			_lock = nullptr;
		}

		return true;
	}


	template<typename T>
	inline bool kavl<T>::Insert(T&& item)
	{
		bool ok = false;
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(_lock, true);

		T* entry = reinterpret_cast<T*>(RtlInsertElementGenericTableAvl(_table, (PVOID)&item, sizeof(T), nullptr));
		//This function is a shallow copy, you must copy it manually
		if (entry)
		{
			memset(entry, 0, sizeof(T));
			*entry = move(item);
			ok = true;
		}

		ExReleaseResourceLite(_lock);
		KeLeaveCriticalRegion();

		return ok;
	}


	template<typename T>
	inline T* kavl<T>::Find(const T& item)
	{
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(_lock, true);

		T* found = reinterpret_cast<T*>(RtlLookupElementGenericTableAvl(_table, (PVOID)&item));

		ExReleaseResourceLite(_lock);
		KeLeaveCriticalRegion();

		return found;
	}


	template<typename T>
	inline void kavl<T>::Remove(T* item)
	{
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(_lock, true);

		if (MmIsAddressValid(item))
		{
			//Execute destructor
			item->~T();
			RtlDeleteElementGenericTableAvl(_table, item);
		}


		ExReleaseResourceLite(_lock);
		KeLeaveCriticalRegion();
	}


	template<typename T>
	inline ULONG kavl<T>::Size()
	{
		return RtlNumberGenericTableElementsAvl(_table);
	}

}
