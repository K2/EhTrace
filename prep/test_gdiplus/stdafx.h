// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <gdiplus.h>

#include <locale.h>
extern "C" FARPROC AMain;

typedef struct _ExecutionBlock {
	DWORD64 BlockFrom;
	DWORD64 TSC;
	ULONG InternalID;
	ULONG TID;
	HANDLE hThr;
	void *handle;
	void *insn;
	size_t csLen;
	ULONG SEQ;
	ULONG HookCnt; // this should bring us back into 64 bit alignment naturally
	void* Hooks;
	PEXCEPTION_POINTERS pExeption; // filed out on entry to handler
								   //PCONTEXT pContextRecord;	// secondary context acquired by getthreadcontext
	LPVOID DisabledUntil;
} ExecutionBlock, *PExecutionBlock;