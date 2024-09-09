#pragma warning(disable : 5040)

#include <etwhook_init.hpp>
#include <kstl/ksystem_info.hpp>
#include <etwhook_utils.hpp>
#include <kstl/kpe_parse.hpp>

enum EtwpTrace
{
	EtwpStartTrace      = 1,
	EtwpStopTrace       = 2,
	EtwpQueryTrace      = 3,
	EtwpUpdateTrace     = 4,
	EtwpFlushTrace      = 5
};

constexpr auto SyscallHookId = 0xf33ul;

#define WNODE_FLAG_TRACED_GUID			0x00020000  // denotes a trace
#define EVENT_TRACE_BUFFERING_MODE      0x00000400  // Buffering mode only
#define EVENT_TRACE_FLAG_SYSTEMCALL     0x00000080  // system calls

#define POOL_TAG 'IWTE'

#pragma warning(disable : 4201)

typedef struct _WNODE_HEADER
{
	ULONG BufferSize;        // Size of entire buffer inclusive of this ULONG
	ULONG ProviderId;    // Provider Id of driver returning this buffer
	union
	{
		ULONG64 HistoricalContext;  // Logger use
		struct
		{
			ULONG Version;           // Reserved
			ULONG Linkage;           // Linkage field reserved for WMI
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	union
	{
		ULONG CountLost;         // Reserved
		HANDLE KernelHandle;     // Kernel handle for data block
		LARGE_INTEGER TimeStamp; // Timestamp as returned in units of 100ns
								 // since 1/1/1601
	} DUMMYUNIONNAME2;
	GUID Guid;                  // Guid for data block returned with results
	ULONG ClientContext;
	ULONG Flags;             // Flags, see below
} WNODE_HEADER;

#pragma warning(default : 4201)

typedef struct _EVENT_TRACE_PROPERTIES
{
	WNODE_HEADER	Wnode;
	ULONG			BufferSize;
	ULONG			MinimumBuffers;
	ULONG			MaximumBuffers;
	ULONG			MaximumFileSize;
	ULONG			LogFileMode;
	ULONG			FlushTimer;
	ULONG			EnableFlags;
	LONG			AgeLimit;
	ULONG			NumberOfBuffers;
	ULONG			FreeBuffers;
	ULONG			EventsLost;
	ULONG			BuffersWritten;
	ULONG			LogBuffersLost;
	ULONG			RealTimeBuffersLost;
	HANDLE			LoggerThreadId;
	ULONG			LogFileNameOffset;
	ULONG			LoggerNameOffset;
} EVENT_TRACE_PROPERTIES;

const GUID CkclSessionGuid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

const GUID NtklSessionGuid = { 0x9E814AAD, 0x3204, 0x11D2, { 0x9A, 0x82, 0x0, 0x60, 0x8, 0xA8, 0x69, 0x39 } };

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
	ULONG64					Unknown[3];
	UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES;

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
);

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetSystemInformation(ULONG infoClass, void* buf, ULONG length);

typedef enum _EVENT_TRACE_INFORMATION_CLASS
{
	EventTraceKernelVersionInformation,
	EventTraceGroupMaskInformation,
	EventTracePerformanceInformation,
	EventTraceTimeProfileInformation,
	EventTraceSessionSecurityInformation,
	EventTraceSpinlockInformation,
	EventTraceStackTracingInformation,
	EventTraceExecutiveResourceInformation,
	EventTraceHeapTracingInformation,
	EventTraceHeapSummaryTracingInformation,
	EventTracePoolTagFilterInformation,
	EventTracePebsTracingInformation,
	EventTraceProfileConfigInformation,
	EventTraceProfileSourceListInformation,
	EventTraceProfileEventListInformation,
	EventTraceProfileCounterListInformation,
	EventTraceStackCachingInformation,
	EventTraceObjectTypeFilterInformation,
	MaxEventTraceInfoClass
} EVENT_TRACE_INFORMATION_CLASS;

typedef struct _EVENT_TRACE_PROFILE_COUNTER_INFORMATION
{
	EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
	HANDLE TraceHandle;
	ULONG ProfileSource[1];
} EVENT_TRACE_PROFILE_COUNTER_INFORMATION, * PEVENT_TRACE_PROFILE_COUNTER_INFORMATION;

typedef struct _EVENT_TRACE_SYSTEM_EVENT_INFORMATION
{
	EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
	HANDLE TraceHandle;
	ULONG HookId[1];
} EVENT_TRACE_SYSTEM_EVENT_INFORMATION, * PEVENT_TRACE_SYSTEM_EVENT_INFORMATION;

const ULONG SystemPerformanceTraceInformation = 31;


static unsigned char* GetEtwpMaxPmcCounter()
{

	//PAGE:00000001409DB8DE 44 3B 05 57 57 37 00                          cmp     r8d, cs:EtwpMaxPmcCounter
	//PAGE : 00000001409DB8E5 0F 87 EC 00 00 00                           ja      loc_1409DB9D7
	//PAGE : 00000001409DB8EB 83 B9 2C 01 00 00 01                        cmp     dword ptr[rcx + 12Ch], 1
	//PAGE:00000001409DB8F2 0F 84 DF 00 00 00                             jz      loc_1409DB9D7
	//PAGE : 00000001409DB8F8 48 83 B9 F8 03 00 00 00                     cmp     qword ptr[rcx + 3F8h], 0
	//PAGE:00000001409DB900 75 0D                                         jnz     short loc_1409DB90F

	//Windows 18362 and later
	if (kstd::SysInfoManager::getInstance()->getBuildNumber() < 18362)
		return nullptr;

	void* kernelImageBase = FindModuleBase(L"ntoskrnl.exe", 0);

	void* p = kstd::PatternFindSections(
		kernelImageBase,
		"\x44\x3b\x05\x00\x00\x00\x00\x0f\x87\x00\x00\x00\x00\x83\xb9\x00\x00\x00\x00\x01\x0f\x84\x00\x00\x00\x00\x48\x83\xb9\x00\x00\x00\x00\x00\x75\x00",
		"xxx????xx????xx????xxx????xxx????xx?",
		"PAGE");

	if (p)
	{
		LONG offset = *reinterpret_cast<const LONG*>(reinterpret_cast<const char*>(p) + 3);
		return reinterpret_cast<unsigned char*>(p) + 7 + offset;
	}
	else
		return nullptr;
}

EtwInitilizer::EtwInitilizer()
	:
	_isActive(false),
	_halPrivateDispatchTable(0)
{
	UNICODE_STRING funcName = {};

	RtlInitUnicodeString(&funcName, L"HalPrivateDispatchTable");
	_halPrivateDispatchTable = reinterpret_cast<UINT_PTR*>(MmGetSystemRoutineAddress(&funcName));

	if (!_halPrivateDispatchTable)
	{
		LOG_ERROR("failed to get HalPrivateDispatchTable");
	}
}

EtwInitilizer::~EtwInitilizer()
{
	EndTrace();
}

NTSTATUS EtwInitilizer::StartTrace()
{
	if (_isActive)
		return STATUS_SUCCESS;

	NTSTATUS status = StartStopTrace(true);

	if (NT_SUCCESS(status))
		_isActive = true;

	return status;
}

NTSTATUS EtwInitilizer::EndTrace()
{
	if (!_isActive)
		return STATUS_SUCCESS;

	NTSTATUS status = StartStopTrace(false);

	if (NT_SUCCESS(status))
		_isActive = false;

	return status;
}

//In fact, this needs to call ZwSetSystemInformation,
//but I can't find suitable documentation and articles,
//so I can only reverse Windows manually, and finally get the result
NTSTATUS EtwInitilizer::OpenPmcCounter()
{
	NTSTATUS status = STATUS_SUCCESS;
	PEVENT_TRACE_PROFILE_COUNTER_INFORMATION countInfo = 0;
	PEVENT_TRACE_SYSTEM_EVENT_INFORMATION eventInfo = 0;

	if (!_isActive)
		return STATUS_FLT_NOT_INITIALIZED;

	do
	{
		//Get the loggerid of ckcl_context
		ULONG*** etwpDebuggerData = reinterpret_cast<ULONG***>(
			kstd::SysInfoManager::getInstance()->getSysInfo()->EtwpDebuggerData);

		if (!etwpDebuggerData)
		{
			status = STATUS_NOT_SUPPORTED;
			LOG_ERROR("failed to get EtwpDebuggerData!");
			break;
		}

		//This can be referred to the first version of ETW HOOK, which is abbreviated here
		auto loggerId = etwpDebuggerData[2][2][0];

		countInfo = kalloc<EVENT_TRACE_PROFILE_COUNTER_INFORMATION>(NonPagedPool, POOL_TAG);
		if (!countInfo)
		{
			LOG_ERROR("failed to alloc memory for pmc_count!");
			status = STATUS_MEMORY_NOT_ALLOCATED;
			break;
		}
		//First set PMC Count. We only care about one hookid, which is the hookid of syscall 0xf33 profile source. Set it casually.
		countInfo->EventTraceInformationClass = EventTraceProfileCounterListInformation;
		countInfo->TraceHandle = ULongToHandle(loggerId);//This is actually loggerid
		countInfo->ProfileSource[0] = 1;//Fill in any

		unsigned char* etwpMaxPmcCounter = GetEtwpMaxPmcCounter();

		unsigned char original = 0;

		if (etwpMaxPmcCounter)
		{
			original = *etwpMaxPmcCounter;
			if (original <= 1)
				*etwpMaxPmcCounter = 2;
		}

		status = ZwSetSystemInformation(SystemPerformanceTraceInformation, countInfo, sizeof EVENT_TRACE_PROFILE_COUNTER_INFORMATION);

		if (etwpMaxPmcCounter)
		{
			if (original <= 1)
				*etwpMaxPmcCounter = original;
		}

		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("failed to configure pmc counter, errcode=%x", status);
			break;
		}


		//Then you only need one to set the PMC Event hookid
		eventInfo = kalloc<EVENT_TRACE_SYSTEM_EVENT_INFORMATION>(NonPagedPool, POOL_TAG);
		if (!eventInfo)
		{
			LOG_ERROR("failed to alloc memory for eventInfo!");
			status = STATUS_MEMORY_NOT_ALLOCATED;
			break;
		}

		eventInfo->EventTraceInformationClass = EventTraceProfileEventListInformation;
		eventInfo->TraceHandle = ULongToHandle(loggerId);
		eventInfo->HookId[0] = SyscallHookId;

		status = ZwSetSystemInformation(SystemPerformanceTraceInformation, eventInfo, sizeof EVENT_TRACE_SYSTEM_EVENT_INFORMATION);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("failed to configure pmc event, errcode=%x", status);
			break;
		}

	} while (false);

	if (countInfo)
		ExFreePool(countInfo);

	if (eventInfo)
		ExFreePool(eventInfo);

	return status;
}

NTSTATUS EtwInitilizer::StartStopTrace(bool start)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	CKCL_TRACE_PROPERTIES* ckclProperty = 0;
	ULONG lengthReturned = 0;

	do
	{
		ckclProperty = kalloc<CKCL_TRACE_PROPERTIES>(NonPagedPool, POOL_TAG, PAGE_SIZE);
		if (!ckclProperty)
		{
			LOG_ERROR("failed to alloc memory for etw property!");
			status = STATUS_MEMORY_NOT_ALLOCATED;
			break;
		}

		memset(ckclProperty, 0, PAGE_SIZE);
		ckclProperty->Wnode.BufferSize = PAGE_SIZE;
		ckclProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		ckclProperty->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
		ckclProperty->Wnode.Guid = CkclSessionGuid;
		ckclProperty->Wnode.ClientContext = 1;
		ckclProperty->BufferSize = sizeof(ULONG);
		ckclProperty->MinimumBuffers = ckclProperty->MaximumBuffers = 2;
		ckclProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

		status = ZwTraceControl(start ? EtwpStartTrace : EtwpStopTrace, ckclProperty, PAGE_SIZE, ckclProperty, PAGE_SIZE, &lengthReturned);

		//sometimes may return value is STATUS_OBJECT_NAME_COLLISION
		if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION)
		{
			LOG_ERROR("failed to enable kernel logger etw trace, errcode=%x", status);
			break;
		}

		if (start)
		{
			ckclProperty->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;

			status = ZwTraceControl(EtwpUpdateTrace, ckclProperty, PAGE_SIZE, ckclProperty, PAGE_SIZE, &lengthReturned);
			if (!NT_SUCCESS(status))
			{
				LOG_ERROR("failed to enable syscall etw, errcode=%x", status);
				StartStopTrace(false);
				break;
			}
		}

	} while (false);

	if (ckclProperty)
		ExFreePool(ckclProperty);

	return status;
}
