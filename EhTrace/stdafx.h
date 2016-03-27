#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#pragma once
#define _CRT_SECURE_NO_WARNINGS 1
#define _WIN32_WINNT 0x601
#include "targetver.h"

#define EhHooks 1

#include <intrin.h>
#include <immintrin.h>
#include <stdio.h>
#include <tchar.h>
#include <capstone.h>

#include <Windows.h>

#include <signal.h>
#include <synchapi.h>
#include <TlHelp32.h>
#include <Winternl.h>
#include <wchar.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#define WORD_BIT_SHIFT 6
#define WORD_MOD_SIZE 63

typedef unsigned short u_int16_t;
typedef unsigned char u_int8_t;

// Overall Context through the handler
// any state we capture + log + extra 
// emulator, decision logic verbose data
typedef struct _ExecutionBlock {
	DWORD64 BlockFrom;
	DWORD64 TSC;
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

bool AmIinThreadTable();
bool InitThreadTable(ULONGLONG EstMaxTID);
bool IsThreadInTable(ULONGLONG tid, bool Inst);
void ExitThreadTable(ULONGLONG tid, bool Inst);
void EnterThreadTable(ULONGLONG tid, bool Inst);

void _DumpContext(PExecutionBlock ExceptionInfo);
void DoRandomTestStuff(ULONG Arg);

#include "GlobLog.h"
