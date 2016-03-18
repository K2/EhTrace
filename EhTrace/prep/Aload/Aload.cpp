// Aload.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

BOOL EnablePrivilege(TCHAR *szPrivName, BOOL fEnable)
{
	TOKEN_PRIVILEGES tp;
	LUID	luid;
	HANDLE	hToken;

	if (!LookupPrivilegeValue(NULL, szPrivName, &luid))
		return FALSE;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;

	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

	CloseHandle(hToken);

	return (GetLastError() == ERROR_SUCCESS);
}


BOOL EnableDebugPrivilege()
{
	return EnablePrivilege(SE_DEBUG_NAME, TRUE);
}

BOOL InjectDll(DWORD pID, wchar_t *DllName) {
	HMODULE hDll = GetModuleHandle(L"kernel32.dll");
	if (hDll == NULL) {
		wprintf(L"Get handle of kernel32.dll error.\n");
		return FALSE;
	}

	LPTHREAD_START_ROUTINE pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hDll, "LoadLibraryW");
	if (pThreadProc == NULL) {
		wprintf(L"Get address of LoadLibraryW() error.\n");
		return FALSE;
	}


	HANDLE hProcess = INVALID_HANDLE_VALUE;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	if (hProcess == INVALID_HANDLE_VALUE) {
		wprintf(L"Open process error.\n");
		return FALSE;
	}

	DWORD bufSizeForDllName = (DWORD)(wcslen(DllName) + 1)*sizeof(wchar_t);
	LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, bufSizeForDllName, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL) {
		wprintf(L"Memory Allocation failed.\n");
		CloseHandle(hProcess);
		return FALSE;
	}

	size_t bytesWritten = 0;
	if ((!WriteProcessMemory(hProcess, pRemoteBuf, DllName, bufSizeForDllName, &bytesWritten)) || bytesWritten != bufSizeForDllName) {
		wprintf(L"Write process memory error.\n");
		CloseHandle(hProcess);
		return FALSE;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);

	if (hThread == NULL) {
		wprintf(L"Create remote thread failed.\n");
		CloseHandle(hProcess);
		return FALSE;
	}

	if (WaitForSingleObject(hThread, INFINITE) != WAIT_OBJECT_0) {
		wprintf(L"Thread run failed.\n");
		CloseHandle(hThread);
		CloseHandle(hProcess);
		return FALSE;
	}
	else {
		CloseHandle(hThread);
		CloseHandle(hProcess);
		return TRUE;
	}
}


int wmain(int argc, wchar_t* argv[])
{
	DWORD pid = 0;
	wchar_t *DllPath = NULL;
	bool good = false;

	if (argc == 3)
	{
		DllPath = argv[1];
		pid = wcstol(argv[2], 0, 10);

		if (pid != 0 && pid != LONG_MAX)
			good = PathFileExistsW(DllPath);
	}
	if(!good)
	{
		wprintf(L"%s c:\\full\\path\\to\\EhTrace.dll 1234\n", argv[0]);
		wprintf(L"specify DLL path and PID only\n");
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

	return 0;
}

