#pragma once

#include <refs.hpp>
#include <etwhook_base.hpp>
#include <etwhook_init.hpp>
#include <kstl/kavl.hpp>

class EtwHookManager : public EtwBase
{
private:
	struct HookMapEntry
	{
		void* original;
		void* target;

		bool operator==(const HookMapEntry& rhs) const { return this->original == rhs.original; }
		bool operator<(const HookMapEntry& rhs) const { return this->original < rhs.original; }
		bool operator>(const HookMapEntry& rhs) const { return this->original > rhs.original; }
	};

public:
	//Singleton
	static EtwHookManager* GetInstance();

	NTSTATUS Initialize();

	NTSTATUS Destory();

	NTSTATUS add_hook(void* original, void* target);

	NTSTATUS remove_hook(void* original);

private:
	EtwHookManager();
	~EtwHookManager();

	static void HalCollectPmcCountersHook(void* context, ULONGLONG traceBufferEnd);

	void TraceStackToSyscall();

	void ProcessSyscall(void** stackPos);

private:
	typedef void (*HalCollectPmcCountersProc)(void*, ULONGLONG);

	static HalCollectPmcCountersProc _originalHalCollectPmcCounters;

	kstd::kavl<HookMapEntry> _hookMap;

	EtwInitilizer _initilizer;

	static EtwHookManager* _instance;

	static const ULONG _halCollectPmcCountersIndex = 73;

	void* _kiSystemServiceRepeat;
};
