// Astrace.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Symbolize.h"

#define BUFSIZE 4096
#define SYMPATH_MAX (1024 * 32 * sizeof(wchar_t))

PROCESS_INFORMATION pi = { 0 };
STARTUPINFO si = { 0 };


wchar_t *ToRun = NULL;
wchar_t  buffer[BUFSIZE] = L"";
wchar_t* EhTrace = NULL;
wchar_t** lppPart = { NULL };
extern wchar_t *optarg;
extern PConfigContext pConfig;

using namespace AStrace;
using namespace System;

void ShowHelp(wchar_t* argv[])
{
	wprintf(L"\nusage:\t%s -x required\n", argv[0]);
	wprintf(L"\t\t\t  -x [path-to-exe] (trace execution)\n");
	wprintf(L"\t\t\t  -E [path-to-EhTrace.dll]\n");
	wprintf(L"\nSupply at least an exe to trace (-x), EhTrace.DLL must be in the current directory or specified by -E\n");

	return;
}

// call's remote thread
void CallInject(DWORD PID)
{
	InjectDll(PID, EhTrace);
}

int wmain(int argc, wchar_t* argv[])
{
	int c;
	HRESULT hr;
	HANDLE hSymbolCache = INVALID_HANDLE_VALUE;
	DWORD ExitCode = 0;
	marshal_context context;
	wchar_t* szSymbolCache = NULL;
	bool UseSymbolCache = false;

	si.cb = sizeof(si);

	if (CreateConfig())
	{
		wprintf(L"Unable to setup configuration space shared mapping.");
		return -1;
	}

	DWORD retval = GetFullPathName(L"EhTrace.DLL", BUFSIZE, buffer, lppPart);
	while ((c = getopt(argc, argv, L"x:E:sc:C:")) != -1)
	{
		switch (c)
		{
		case L'x':
			ToRun = _wcsdup(optarg);
			break;
		case L'E':
			EhTrace = _wcsdup(optarg);
			break;
		case L's':
			pConfig->BasicSymbolsMode = true;
			break;
		case L'C':
			szSymbolCache = _wcsdup(optarg);
			break;
		case L'c':
			szSymbolCache = _wcsdup(optarg);
			UseSymbolCache = true;
			break;
		default:
			wprintf(L"unknown argument [%s]\n", optarg);
			break;
		}
	}

	if (argc <= 1 || !retval || !ToRun)
	{
		ShowHelp(argv);
		return -2;
	}

	EhTrace = buffer;
	wprintf(L"Starting %s (injection DLL %s) \n", ToRun, EhTrace);

	BOOL RV = CreateProcess(ToRun, ToRun, NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (!RV)
	{
		LPVOID lpMsgBuf;
		DWORD dw = GetLastError();
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (wchar_t*)&lpMsgBuf, 0, NULL);

		wprintf(L"failed at CreateProcess()\nCommand=%s\nMessage=%s\n\n", ToRun, (wchar_t*)lpMsgBuf);
		LocalFree(lpMsgBuf);
		return dw;
	}
	// this main thread exit's after calling LoadLibrary so no worry on some wonky priority
	wprintf(L"Loading Atrace DLL");
	HANDLE hTestThr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CallInject, (LPVOID)pi.dwProcessId, THREAD_PRIORITY_HIGHEST, NULL);
	WaitForSingleObject(hTestThr, INFINITE);
	SuspendThread(hTestThr);


	wprintf(L"Symbolizing code, this step can take time.");
	// do Symbols
	SymbolSetup::SymSetup(&pi);
	int SymCnt = Globals::SymCtx->ListAllSymbols->Count;
	int MarshaledSymbols = 0;
	wprintf(L" %d symbols prepared\n", SymCnt);

	// load Symbols into config space as log addresses
	ConnectSymbols(SymCnt);
	for (int i = 0; i < SymCnt; i++)
	{
		bool HasNoName = String::IsNullOrWhiteSpace(Globals::SymCtx->ListAllSymbols[i]->Name);
		bool HasNoUDName = String::IsNullOrWhiteSpace(Globals::SymCtx->ListAllSymbols[i]->UDName);

		if (HasNoName && HasNoUDName)
			continue;
		MarshaledSymbols++;

		pConfig->SymTab[i].Address = Globals::SymCtx->ListAllSymbols[i]->Address;
		pConfig->SymTab[i].Length = Globals::SymCtx->ListAllSymbols[i]->Length;

		if (!HasNoName)
		{
			pConfig->SymTab[i].Name = context.marshal_as<const wchar_t*>(Globals::SymCtx->ListAllSymbols[i]->Name);
			pConfig->SymTab[i].NameLen = wcslen(pConfig->SymTab[i].Name);
		}

		if (!HasNoUDName)
		{
			pConfig->SymTab[i].UDName = context.marshal_as<const wchar_t*>(Globals::SymCtx->ListAllSymbols[i]->UDName);
			pConfig->SymTab[i].UDNameLen = wcslen(pConfig->SymTab[i].UDName);
		}
	}
	wprintf(L"Symbols marshaled into shared memory\n");

	if (szSymbolCache)
	{
		DiskSymbol ds;
		if (UseSymbolCache)
		{
			hSymbolCache = CreateFile(szSymbolCache, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);



		}
		else
		{

			wprintf(L"Caching Symbols to file %s\n", szSymbolCache);

			hSymbolCache = CreateFile(szSymbolCache, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
			for (int j = 0; j < MarshaledSymbols; j++)
			{
				ds.Address = pConfig->SymTab[j].Address;
				ds.Length = pConfig->SymTab[j].Length;
				//ds.NameLen = pConfig->SymTab[j].NameLen;
				//ds.UDNameLen = pConfig->SymTab[j].UDNameLen;
				if(pConfig->SymTab[j].Name && wcslen(pConfig->SymTab[j].Name) < sizeof(ds.Name) / sizeof(wchar_t))
					wcscpy_s(ds.Name, pConfig->SymTab[j].Name);
				if(pConfig->SymTab[j].UDName && wcslen(pConfig->SymTab[j].UDName) < sizeof(ds.UDName) / sizeof(wchar_t))
					wcscpy_s(ds.UDName, pConfig->SymTab[j].UDName);

				WriteFile(hSymbolCache, &ds, sizeof(DiskSymbol), NULL, NULL);

				//WriteFile(hSymbolCache, pConfig->SymTab[j].Name, ds.NameLen, NULL, NULL);
				//WriteFile(hSymbolCache, pConfig->SymTab[j].UDName, ds.UDNameLen, NULL, NULL);
			}
		}
		CloseHandle(hSymbolCache);
	}


	// make sure our thread is keyed up.
	Sleep(1000);
	ResumeThread(hTestThr);
	ResumeThread(pi.hThread);

	wprintf(L"Process started & waiting for exit\n");
	WaitForSingleObject(pi.hProcess, INFINITE);

	// Get the exit code.
	RV = GetExitCodeProcess(pi.hProcess, &ExitCode);

	// Close the handles.
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	if (!RV)
	{
		// Could not get exit code.
		wprintf(L"Executed command but couldn't get exit code.\nCommand=%s\n", ToRun);
		return -3;
	}


	return ExitCode;
}

