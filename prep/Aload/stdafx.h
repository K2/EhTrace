// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <wchar.h>
#include "Shlwapi.h"

#include <windows.h>

#include <TlHelp32.h>


BOOL EnablePrivilege(TCHAR *szPrivName, BOOL fEnable);
BOOL EnableDebugPrivilege();
BOOL InjectDll(DWORD pID, wchar_t *DllName);

#define IN_ALOAD true

int GetModStatsToFile(wchar_t *modStats, DWORD pid);
PMODULEENTRY32W GetModStats(DWORD pid, int *Cnt);