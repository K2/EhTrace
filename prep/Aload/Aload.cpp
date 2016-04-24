// Aload.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


int wmain(int argc, wchar_t* argv[])
{
	DWORD pid = 0;
	wchar_t *DllPath = NULL;
	wchar_t *modStats = NULL;
	bool good = false;

	if (argc == 3)
	{
		DllPath = argv[1];
		pid = wcstol(argv[2], 0, 10);

		if (pid != 0 && pid != LONG_MAX)
			good = PathFileExistsW(DllPath);
	}
	else if (argc == 4)
	{
		DllPath = argv[1];
		modStats = argv[2];
		pid = wcstol(argv[3], 0, 10);

		if (pid != 0 && pid != LONG_MAX)
			good = PathFileExistsW(DllPath);
	}

	if(!good)
	{
		wprintf(L"%s c:\\full\\path\\to\\EhTrace.dll 1234\n", argv[0]);
		wprintf(L"specify [DLL path] and [PID]\n or \n[DLL path] [mod-stats file] and [PID]\n");
		wprintf(L"%s c:\\full\\path\\to\\EhTrace.dll c:\\temp\\trace-mod.stats 1234\n", argv[0]);
		wprintf(L"trace-mod.stats file is created & used if you want symbol loads later.\n");
		exit(-1);
	}

	wprintf(L"Loading DLL %s into PID %d\n", DllPath, pid);
	EnableDebugPrivilege();
	if (InjectDll(pid, DllPath))
		wprintf(L"Load success\n");
	else {
		wprintf(L"Load failed\n");
		return -2;
	}

	return GetModStatsToFile(modStats, pid);
}

