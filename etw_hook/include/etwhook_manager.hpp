#pragma once

#include <refs.hpp>
#include <etwhook_base.hpp>
#include <etwhook_init.hpp>

typedef void(__fastcall* HOOK_CALLBACK)(_In_ unsigned int systemCallIndex, _Inout_ void** systemCallFunction);

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

	NTSTATUS Initialize(HOOK_CALLBACK hookCallback);

	NTSTATUS Destory();

private:
	EtwHookManager();
	~EtwHookManager();

	static void HalCollectPmcCountersHook(void* context, ULONGLONG traceBufferEnd);

	void TraceStackToSyscall();

	void ProcessSyscall(unsigned systemCallIndex, void** stackPos);

private:
	typedef void (*HalCollectPmcCountersProc)(void*, ULONGLONG);

	bool _isInitialized;

	static HalCollectPmcCountersProc _originalHalCollectPmcCounters;

	EtwInitilizer _initilizer;

	static EtwHookManager* _instance;

	static const ULONG _halCollectPmcCountersIndex = 73;

	HOOK_CALLBACK _hookCallback;

	void* _kiSystemServiceRepeat;
};
