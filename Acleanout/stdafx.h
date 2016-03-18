// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"
#define _CRT_DISABLE_PERFCRIT_LOCKS

#include <stdio.h>
#include <tchar.h>

#include <Windows.h>
#include <TlHelp32.h>

#include <capstone.h>
// Overall Context through the handler
// any state we capture + log + extra 
// emulator, decision logic verbose data
typedef struct _ExecutionBlock {
	DWORD64 BlockFrom;
	ULONG InternalID;
	ULONG TID;
	HANDLE hThr;
	ULONG SEQ;
	csh handle;
	cs_insn *insn;
	size_t csLen;

	PEXCEPTION_POINTERS pExeption; // filed out on entry to handler
								   //PCONTEXT pContextRecord;	// secondary context acquired by getthreadcontext
} ExecutionBlock, *PExecutionBlock;


#include "EhTrace\GlobLog.h"