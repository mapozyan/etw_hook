#pragma warning(disable : 5040)

#include <etwhook_manager.hpp>
#include <kstl/ksystem_info.hpp>
#include <kstl/kpe_parse.hpp>
#include <etwhook_utils.hpp>
#include <intrin.h>

EtwHookManager* EtwHookManager::_instance = 0;

EtwHookManager::HalCollectPmcCountersProc EtwHookManager::_originalHalCollectPmcCounters;


EtwHookManager* EtwHookManager::GetInstance()
{
	if (!_instance)
		_instance = new EtwHookManager;

	return _instance;
}


NTSTATUS EtwHookManager::Initialize()
{
	auto status = STATUS_UNSUCCESSFUL;

	//Check whether the memory of the singleton is allocated
	if (!_instance)
		return STATUS_MEMORY_NOT_ALLOCATED;

	//This method does not support win7
	auto sysInfo = kstd::SysInfoManager::getInstance();

	if (!sysInfo)
		return STATUS_INSUFFICIENT_RESOURCES;

	if (sysInfo->getBuildNumber() <= 7601)
	{
		LOG_ERROR("current os version is not supported!\r\n");
		return STATUS_NOT_SUPPORTED;
	}

	do {
		status = _initilizer.StartTrace();
		if (!NT_SUCCESS(status))
			break;

		/*set value above 1*/

		status = _initilizer.OpenPmcCounter();
		if (!NT_SUCCESS(status))
			break;


		UINT_PTR* halPrivateDispatchTable = _initilizer.GetHalPrivateDispatchTable();
		if (!halPrivateDispatchTable)
		{
			status = STATUS_UNSUCCESSFUL;
			LOG_ERROR("failed to get HalPrivateDispatchTable address!\r\n");
			break;
		}

		_disable();

		_originalHalCollectPmcCounters = reinterpret_cast<HalCollectPmcCountersProc>(halPrivateDispatchTable[_halCollectPmcCountersIndex]);

		halPrivateDispatchTable[_halCollectPmcCountersIndex] = reinterpret_cast<ULONG_PTR>(HalCollectPmcCountersHook);

		_enable();


	} while (false);


	//clean up

	//if fail

	//if suc

	return status;
}


NTSTATUS EtwHookManager::Destory()
{
	if (!_instance)
		return STATUS_MEMORY_NOT_ALLOCATED;

	delete _instance;
	_instance = 0;

	LARGE_INTEGER delayTime = {};
	delayTime.QuadPart = -10 * 1000000 * 2;
	KeDelayExecutionThread(KernelMode, false, &delayTime);

	return STATUS_SUCCESS;
}


NTSTATUS EtwHookManager::add_hook(void* original, void* target)
{
	if (!_instance)
		return STATUS_FLT_NOT_INITIALIZED;

	bool ok = _hookMap.Insert({original, target});

	return ok ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

}


NTSTATUS EtwHookManager::remove_hook(void* original)
{
	if (!_instance)
		return STATUS_FLT_NOT_INITIALIZED;

	auto entry = _hookMap.Find({original, nullptr});

	if (!entry)
		return STATUS_NOT_FOUND;

	_hookMap.Remove(entry);

	return STATUS_SUCCESS;
}


void EtwHookManager::HalCollectPmcCountersHook(void* context, ULONGLONG traceBufferEnd)
{
	// Sometimes the interrupt will go to this function. Here we can judge whether the IRQL must be DPC_LEVEL? It won't work if it is higher than this level.
	if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
		EtwHookManager::GetInstance()->TraceStackToSyscall();

	return _originalHalCollectPmcCounters(context, traceBufferEnd);
}


//sys_call_etw_entry
//48 83 EC 50                   sub     rsp, 50h
//48 89 4C 24 20                mov[rsp + 20h], rcx
//48 89 54 24 28                mov[rsp + 28h], rdx
//4C 89 44 24 30                mov[rsp + 30h], r8
//4C 89 4C 24 38                mov[rsp + 38h], r9
//4C 89 54 24 40                mov[rsp + 40h], r10
//49 8B CA                      mov     rcx, r10
//E8 54 A5 19 00                call    PerfInfoLogSysCallEntry
//48 8B 4C 24 20                mov     rcx, [rsp + 20h]
//48 8B 54 24 28                mov     rdx, [rsp + 28h]
//4C 8B 44 24 30                mov     r8, [rsp + 30h]
//4C 8B 4C 24 38                mov     r9, [rsp + 38h]
//4C 8B 54 24 40                mov     r10, [rsp + 40h]
//48 83 C4 50                   add     rsp, 50h
//49 8B C2                      mov     rax, r10
//FF D0                         call    rax
/*Finding a way is
1.First determine whether there is a magic number (it seems unnecessary? Because this method only system calls will enter the filter function)
2.Determine the start and end addresses of KiSyscall64
3.After traversing the stack, is it at the start and end addresses? If so, it means the stack is currently at

rsp->KiSyscall64.call    PerfInfoLogSysCallEntry
rsp+0x48==TargetSystemCall

*/

EtwHookManager::EtwHookManager()
	:
	_hookMap()
{

	void* kernelImageBase = FindModuleBase(L"ntoskrnl.exe", 0);

	//Note that this method is not rigorous! There is no direct readmsr IA32_LSTAR and then use the disassembly engine to parse the rigorous
	//KiSystemServiceRepeat:
	//	4C 8D 15 85 6F 9F 00          lea     r10, KeServiceDescriptorTable
	//	4C 8D 1D FE 20 8F 00          lea     r11, KeServiceDescriptorTableShadow
	//	F7 43 78 80 00 00 00          test    dword ptr[rbx + 78h], 80h; GuiThread
	//KiSystemServiceRepeat must be located in KiSystemCall64, which directly searches for the signature code

	_kiSystemServiceRepeat = kstd::patternFindSections(kernelImageBase,
		"\x4c\x8d\x15\x00\x00\x00\x00\x4c\x8d\x1d\x00\x00\x00\x00\xf7\x43",
		"xxx????xxx????xx", ".text");

	_hookMap.Initialize();
}


EtwHookManager::~EtwHookManager()
{
	_initilizer.EndTrace();

	_disable();
	_initilizer.GetHalPrivateDispatchTable()[_halCollectPmcCountersIndex] = reinterpret_cast<ULONG_PTR>(_originalHalCollectPmcCounters);
	_enable();

	_hookMap.Destory();
}


void EtwHookManager::TraceStackToSyscall()
{
	if (ExGetPreviousMode() == KernelMode)
	{
		return;
	}

	PVOID* stackLimit = reinterpret_cast<PVOID*>(__readgsqword(0x1A8));

	PVOID* stackPos = reinterpret_cast<PVOID*>(_AddressOfReturnAddress());

	constexpr auto MAGIC1 = 0x501802;
	constexpr auto MAGIC2 = 0xf33;

	do
	{

		if (!_kiSystemServiceRepeat)
		{
			LOG_ERROR("failed to find KiSystemServiceRepeat\r\n");
			break;
		}

		/*
		*
		*			max
					...
					...
		stackPos->	xxx
					...
					magic_number
					...
					syscall   <-Start from the top
		*/

		for (; stackPos < stackLimit; ++stackPos)
		{
			PUSHORT stackAsUshort = reinterpret_cast<PUSHORT>(stackPos);

			if (*stackAsUshort != MAGIC2)
				continue;

			++stackPos;

			PULONG stackAsUlong = reinterpret_cast<PULONG>(stackPos);

			if (*stackAsUlong != MAGIC1)
				continue;

			for (; stackPos < stackLimit; ++stackPos)
			{
				if ((ULONG_PTR)*stackPos >= (ULONG_PTR)PAGE_ALIGN(_kiSystemServiceRepeat) &&
					(ULONG_PTR)*stackPos <= (ULONG_PTR)PAGE_ALIGN(reinterpret_cast<const char*>(_kiSystemServiceRepeat) + PAGE_SIZE * 2))
				{
					//find
					//Note!!! This cur_stck cannot be 100% guaranteed to be a syscall, because sys_exit will also go here
					ProcessSyscall(stackPos);

					break;
				}
			}

			break;
		}

	} while (false);

}


void EtwHookManager::ProcessSyscall(void** stackPos)
{

	auto entry = _hookMap.Find({stackPos[9], nullptr});

	if (!entry)
		return;

	if (entry->target)
	{
		stackPos[9] = entry->target;
	}
}
