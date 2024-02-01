#include "hooks/hooks.h"
#include <thread>

unsigned long WINAPI initialize(void* instance)
{
	if (dump_memory)
	{
		CreateDirectoryA(E("dumps"), 0);
		DeleteFileA(E("pluto_smasher.txt"));
	}

	if (console_log)
	{
		AllocConsole();
		freopen_s(reinterpret_cast<FILE**>(stdin), E("CONIN$"), E("r"), stdin);
		freopen_s(reinterpret_cast<FILE**>(stdout), E("CONOUT$"), ("w"), stdout);
	}

	if (!hooks::init())
	{
		if (console_log)
			printf(E("[pluto-smasher] failed to setup hooks\n"));

		if (file_log)
			utils::log_to_file(E("[paste-smasher] failed to setup hooks\n"));

		MessageBoxA(0, E("failed to setup hooks"), E("paste-smasher"), 0);
	}
	auto ishandlerSet = AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)hooks::Handler);
	if (!ishandlerSet)
		printf(E("[pluto-smasher] failed to setup handler\n"));

	if (!ishandlerSet)
		utils::log_to_file(E("[paste-smasher] failed to setup handler\n"));

	hooks::SetHardwareBreakpoint(hooks::offsetR_AddDobjToScene,1,ReadWriteBreakpoint);

	for (;;)
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

std::int32_t WINAPI DllMain(const HMODULE instance [[maybe_unused]], const unsigned long reason, const void* reserved [[maybe_unused]])
{
	DisableThreadLibraryCalls(instance);

	switch (reason)
	{
		case DLL_PROCESS_ATTACH:
		{
			if (auto handle = CreateThread(nullptr, NULL, initialize, instance, NULL, nullptr))
				CloseHandle(handle);

			break;
		}
	}

	return true;
}