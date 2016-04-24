// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <wchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>

#include <stdlib.h>
#include <string.h>
#include <msclr\marshal.h>

#include <Windows.h>

#include "dia2.h"
#include <DbgHelp.h>

#include "../../EhTrace/Config.h"

#include <TlHelp32.h>

BOOL EnableDebugPrivilege();
BOOL EnablePrivilege(TCHAR *szPrivName, BOOL fEnable);
BOOL InjectDll(DWORD pID, wchar_t *DllName);

int getopt(int argc, wchar_t **argv, wchar_t *opts);
int CreateConfig();

PMODULEENTRY32W GetModStats(DWORD pid, int *Cnt);

using namespace Dia2Sharp;
using namespace msclr::interop;

namespace AStrace {
	public ref class Globals abstract sealed {
	public:
		static Sym^ SymCtx;
	};
}

using namespace AStrace;