#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>

#pragma warning(disable: 4996)

namespace kstd
{

#define LOG_DEBUG(format,...) \
	kstd::Logger::logPrint(kstd::Logger::LogLevel::Debug, __FUNCTION__, format, __VA_ARGS__)

#define LOG_INFO(format,...) \
	kstd::Logger::logPrint(kstd::Logger::LogLevel::Info, __FUNCTION__, format, __VA_ARGS__)

#define LOG_ERROR(format,...) \
	kstd::Logger::logPrint(kstd::Logger::LogLevel::Error, __FUNCTION__, format, __VA_ARGS__)


	class Logger
	{
	public:
		enum LogLevel
		{
			Debug = 1,
			Info = 2,
			Error = 4
		};

	public:
		static void Initialize(const char* info);
		static NTSTATUS logPrint(LogLevel log_level, const char* function_name, const char* format, ...);
		static void getCurSystemTime(char* buf, size_t size);

	private:
		inline static char _info[100];
	};


	inline void Logger::Initialize(const char* info)
	{
		auto oa = OBJECT_ATTRIBUTES{};
		auto isb = IO_STATUS_BLOCK{};

		memcpy_s(_info, sizeof _info, info, strlen(info) + 1);
	}


	NTSTATUS inline Logger::logPrint(LogLevel log_level, const char* function_name, const char* format, ...)
	{
		auto status = STATUS_SUCCESS;
		char userMessage[412]{};
		char time[100]{};
		va_list args{};
		va_start(args, format);

		status = RtlStringCchVPrintfA(userMessage, sizeof(userMessage), format, args);

		va_end(args);

		getCurSystemTime(time, sizeof time);

		char message[512] = {};
		RtlStringCchPrintfA(message, sizeof(message), "%s\t[tid %05lld]\t[%s]\t", time, reinterpret_cast<UINT_PTR>(PsGetCurrentThreadId()), _info);

		if (NT_SUCCESS(status))
		{
			if (log_level & LogLevel::Debug) {
				RtlStringCchCatA(message, sizeof(message), "[debug]\tfunction name:\t");
				RtlStringCchCatA(message, sizeof(message), function_name);
				RtlStringCchCatA(message, sizeof(message), "\t");
			}
			else if (log_level & LogLevel::Error) {
				RtlStringCchCatA(message, sizeof(message), "[error]\t");
			}
			else if (log_level & LogLevel::Info) {
				RtlStringCchCatA(message, sizeof(message), "[Info]\t");
			}

			RtlStringCchCatA(message, sizeof(message), userMessage);

			RtlStringCchCatA(message, sizeof(message), "\n");

			DbgPrintEx(77, 0, message);
		}

		return status;
	}


	inline void Logger::getCurSystemTime(char* buf, size_t size)
	{
		LARGE_INTEGER systemTime{}, localTime{};
		TIME_FIELDS timeFields{};

		KeQuerySystemTime(&systemTime.QuadPart);
		ExSystemTimeToLocalTime(&systemTime, &localTime);
		RtlTimeToTimeFields(&localTime, &timeFields);
		sprintf_s(buf, size,
			"[%4d-%02d-%02d %02d:%02d:%02d.%03d]",
			timeFields.Year, timeFields.Month, timeFields.Day,
			timeFields.Hour, timeFields.Minute, timeFields.Second, timeFields.Milliseconds);
	}

}

#pragma warning(default : 4996)
