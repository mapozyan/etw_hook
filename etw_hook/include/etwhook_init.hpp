#pragma once

#include <etwhook_base.hpp>

class EtwInitilizer : public EtwBase
{
public:
	EtwInitilizer();
	~EtwInitilizer();

	NTSTATUS StartTrace();
	NTSTATUS EndTrace();

	//Only when this is turned on will the HalPmcCounter function be executed.
	NTSTATUS OpenPmcCounter();

	UINT_PTR* GetHalPrivateDispatchTable() const
	{
		return _halPrivateDispatchTable;
	}

private:
	EtwInitilizer(const EtwInitilizer&) = delete;
	EtwInitilizer& operator=(const EtwInitilizer&) = delete;

	bool      _isOpen;
	UINT_PTR* _halPrivateDispatchTable;
};
