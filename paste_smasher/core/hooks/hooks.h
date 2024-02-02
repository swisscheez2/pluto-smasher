#pragma once

#define console_log 1
#define file_log 1
#define dump_memory 1
enum BreakpointType {
	NoBreakpoint = 0,
	ReadBreakpoint = 1,
	WriteBreakpoint = 2,
	ReadWriteBreakpoint = 3
};
#include "../../dependencies/minhook/minhook.h"
#include "../utils/utils.h"
#include <fstream>

namespace data
{
	inline int alloc_count;
	inline int write_count;
}

namespace hooks
{

	constexpr auto offsetR_AddDobjToScene = 0x7269C9;

	namespace nt_allocate_virtual_memory
	{
		using fn = NTSTATUS(__stdcall*)(     HANDLE    ProcessHandle,
			 PVOID* BaseAddress,
			 ULONG_PTR ZeroBits,
			 PSIZE_T   RegionSize,
			 ULONG     AllocationType,
			 ULONG     Protect);
		NTSTATUS __stdcall hook(      HANDLE    ProcessHandle,
			 PVOID* BaseAddress,
			 ULONG_PTR ZeroBits,
			 PSIZE_T   RegionSize,
			 ULONG     AllocationType,
			 ULONG     Protect);
	}

	namespace allocate_virtual_ex
	{
		using fn = LPVOID(__stdcall*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
		LPVOID __stdcall hook(HANDLE proc, PVOID addr, SIZE_T size, DWORD alloc, DWORD prot);
	}
	LONG CALLBACK Handler(EXCEPTION_POINTERS* pExceptionInfo);
	bool init();



	
	void SetHardwareBreakpoint(DWORD_PTR address, int reg, BreakpointType breakpointType = NoBreakpoint);
}