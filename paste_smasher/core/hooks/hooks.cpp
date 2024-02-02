#include "hooks.h"
#include <tlhelp32.h>
#include <iostream>
#include <dbghelp.h>
#include <bitset>

#pragma comment(lib, "DbgHelp.lib")

hooks::nt_allocate_virtual_memory::fn o_wvm = nullptr;
hooks::allocate_virtual_ex::fn o_avex = nullptr;
LONG CALLBACK hooks::Handler(EXCEPTION_POINTERS* pExceptionInfo)
{
	if (pExceptionInfo->ContextRecord->Eip == offsetR_AddDobjToScene)
	{
		CONTEXT* context = pExceptionInfo->ContextRecord;
		DWORD dr6 = context->Dr6;
		std::cout << "offsetR_AddDobjToScene:  triggered 0x" << std::hex << pExceptionInfo->ContextRecord->Eip << std::endl;
		MessageBox(NULL, L"triggered handler",L"test", MB_OK);
		// Check if DR0 hardware breakpoint was triggered (read or write)
		if (dr6 & 0x1)
		{
			DWORD_PTR address = context->Dr0;
			// Log the EIP value
			DWORD_PTR eipAddress = context->Eip;
			std::cout << "EIP: 0x" << std::hex << eipAddress << std::endl;

			// Capture call stack
			PVOID callStack[100];
			DWORD frames = CaptureStackBackTrace(0, 100, callStack, NULL);

			// Resolve symbols for address and log it
			IMAGEHLP_SYMBOL symbol;
			symbol.SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
			symbol.MaxNameLength = 256;
			if (SymGetSymFromAddr(GetCurrentProcess(), address, NULL, &symbol))
			{
				std::cout << "Memory Address: 0x" << std::hex << address << std::endl;
				std::cout << "Function/Module: " << symbol.Name << std::endl;
			}

			// Check if it was a read operation
			if (dr6 & 0x2)
			{
				// Log read event to console
				std::cout << "Read operation at address 0x" << std::hex << address << std::endl;
			}
			// Check if it was a write operation
			if (dr6 & 0x4)
			{
				// Log write event to console
				std::cout << "Write operation at address 0x" << std::hex << address << std::endl;
			}
		}

		// Emulate push ebx
		context->Esp -= sizeof(DWORD);
		DWORD* pStack = (DWORD*)context->Esp;
		*pStack = context->Ebx;

		context->Eip += 1;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}



bool hooks::init()
{
	const auto ntdll = GetModuleHandleA(E("ntdll.dll"));

	if (!ntdll)
		return false;

	const auto kernel32 = GetModuleHandleA("kernel32.dll");

	if (!kernel32)
		return false;

	const auto syscall_addr = reinterpret_cast<void*>(GetProcAddress(ntdll, E("NtAllocateVirtualMemory")));

	if (!syscall_addr)
		return false;

	const auto alloc_addr = reinterpret_cast<void*>(GetProcAddress(kernel32, E("VirtualAllocEx")));

	if (!alloc_addr)
		return false;

	if (MH_Initialize() != MH_OK)
		return false;

	if (MH_CreateHook(syscall_addr, &hooks::nt_allocate_virtual_memory::hook, (LPVOID*)&o_wvm) != MH_OK)
		return false;

	if (MH_CreateHook(alloc_addr, &hooks::allocate_virtual_ex::hook, (LPVOID*)&o_avex) != MH_OK)
		return false;

	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
		return false;

	if (console_log)
		printf(E("[Pluto-smasher] setup hooks\n"));

	if (file_log)
		utils::log_to_file(E("[Pluto-smasher] setup hooks\n"));

	return true;
}

NTSTATUS __stdcall hooks::nt_allocate_virtual_memory::hook(   HANDLE    ProcessHandle,
	 PVOID* BaseAddress,
	 ULONG_PTR ZeroBits,
	 PSIZE_T   RegionSize,
	 ULONG     AllocationType,
	 ULONG     Protect)
{
	data::write_count++;

	if (console_log)
		printf(E("[Pluto-smasher] nt_allocate_virtual_memory: [handle: %p, addr: %p, ZeroBits: %p, size: %d, AllocationType: %X, Protect: %X]\n"), ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	if (file_log)
		utils::log_to_file(E("[Pluto-smasher] nt_allocate_virtual_memory: [handle: %p, addr: %p, ZeroBits: %p, size: %d, AllocationType: %X, Protect: %X]\n"), ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	/*if (dump_memory)
	{
		char file_name_buf[512];

		sprintf_s(file_name_buf, E("dumps/dmp-a%i-%p-w%i.bin"), data::alloc_count, (void*)BaseAddress, data::write_count);

		const auto file_handle = CreateFileA(file_name_buf, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_NEW, 0, 0);

		if (file_handle != INVALID_HANDLE_VALUE)
		{
			DWORD ret;

			const auto write_status = WriteFile(file_handle, buffer, size, &ret, 0);

			CloseHandle(file_handle);
		}

	}*/

	return o_wvm(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

PVOID __stdcall hooks::allocate_virtual_ex::hook(HANDLE proc, LPVOID addr, SIZE_T size, DWORD type, DWORD prot)
{
	data::alloc_count++;

	const auto allocated_memory = o_avex(proc, addr, size, type, prot);

	if (console_log)
		printf(E("[Pluto-smasher] virtual_alloc_ex: [in_addr: %p, ret_addr: %p, alloc_size: %d, type: %d, prot: %d, idx: %d]\n"), addr, allocated_memory, (int)size, type, prot, data::alloc_count);

	if (file_log)
		utils::log_to_file(E("[Pluto-smasher] virtual_alloc_ex: [in_addr: %p, ret_addr: %p, alloc_size: %d, type: %d, prot: %d, idx: %d]\n"), addr, allocated_memory, (int)size, type, prot, data::alloc_count);

	return allocated_memory;
}





void hooks::SetHardwareBreakpoint(DWORD_PTR address, int reg, BreakpointType breakpointType)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	hThreadSnap = (CreateToolhelp32Snapshot)(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap)
	{
		te32.dwSize = sizeof(THREADENTRY32);
		if (!(Thread32First)(hThreadSnap, &te32))
		{
			(CloseHandle)(hThreadSnap);
			return;
		}
		do
		{
			if (te32.th32OwnerProcessID == (GetCurrentProcessId)() && te32.th32ThreadID != (GetCurrentThreadId)())
			{
				HANDLE hThread = (OpenThread)(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, 0, te32.th32ThreadID);
				if (hThread)
				{
					CONTEXT context;
					context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
					(SuspendThread)(hThread);

					if ((GetThreadContext)(hThread, &context))
					{
						switch (reg)
						{
						case 0:
							context.Dr0 = address; break;
						case 1:
							context.Dr1 = address; break;
						case 2:

							context.Dr2 = address; break;
						case 3:
							context.Dr3 = address; break;
						}
						std::bitset<sizeof(context.Dr7) * 8> dr7;
						std::memcpy(&dr7, &context.Dr7, sizeof(context.Dr7));
						dr7.set(reg * 2); // Flag to enable 'local' debugging for each of 4 registers. Second bit is for global debugging, not working.
				
						switch (breakpointType)
						{
						case ReadBreakpoint:
							// Set breakpoints for read
							context.Dr7 |= (3 << 16); // Set LEN0 and LEN1 to 3 for read
							break;
						case WriteBreakpoint:
							// Set breakpoints for write
							context.Dr7 |= (1 << 18); // Set RW0 to 1 for write
							break;
						case ReadWriteBreakpoint:
							// Set breakpoints for read and write
							//context.Dr7 |= (3 << 16) | (1 << 18); // Set LEN0, LEN1, and RW0
							dr7.set(16 + reg * 4 + 1, true);
							dr7.set(16 + reg * 4 , true);
							break;
						default:
						// dud
							break;
						}
						std::memcpy(&context.Dr7, &dr7, sizeof(context.Dr7));
						//context.Dr7 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6);
						(SetThreadContext)(hThread, &context);
					}
					(ResumeThread)(hThread);
					(CloseHandle)(hThread);
				}
			}
		} while ((Thread32Next)(hThreadSnap, &te32));
		(CloseHandle)(hThreadSnap);
	}
}