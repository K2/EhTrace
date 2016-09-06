#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#pragma once
#define _CRT_SECURE_NO_WARNINGS 1
#define _WIN32_WINNT 0x601
#include "targetver.h"

#define EhHooks 1


#define FLAGS_POST	1
#define FLAGS_PRE	2
#define FLAGS_RESOLVE 4 // disassemble past 1 instruction to get where static linkers join


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

/////// early info on DEBUG MSR method to enable => http://www.ivanlef0u.tuxfamily.org/
//xp sp2 ntoskrnl 5.1.2600, les chiffre indiquent la taille de la struct à passer en argument
typedef enum _DEBUG_CONTROL_CODE {
	DebugSysGetTraceInformation = 1,
	DebugSysSetInternalBreakpoint, //0x38
	DebugSysSetSpecialCall, //0x4
	DebugSysClerSpecialCalls,  //no args kill all special calls
	DebugSysQuerySpecialCalls,
	DebugSysBreakpointWithStatus,
	DebugSysGetVersion, //0x28
	DebugSysReadVirtual = 8, //0x10
	DebugSysWriteVirtual = 9,
	DebugSysReadPhysical = 10,
	DebugSysWritePhysical = 11,
	DebugSysReadControlSpace = 12, //0x18
	DebugSysWriteControlSpace, //0x18
	DebugSysReadIoSpace, //0x20
	DebugSysSysWriteIoSpace, //0x20
	DebugSysReadMsr, //0x10
	DebugSysWriteMsr, //0x10
	DebugSysReadBusData, //0x18
	DebugSysWriteBusData, //0x18
	DebugSysCheckLowMemory,
} DEBUG_CONTROL_CODE;

typedef struct _SYSDBG_VIRTUAL {
	PVOID Address;
	PVOID Buffer;
	ULONG Request;
} SYSDBG_VIRTUAL, *PSYSDBG_VIRTUAL;

typedef struct _SYSDBG_MSR {
	ULONG MSR_Address;
	ULONGLONG DATA;
} SYSDBG_MSR, *PSYSDBG_MSR;


typedef ULONG(__stdcall *NtSystemDebugControl)(DEBUG_CONTROL_CODE ControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
typedef void FighterFunc(void *pCtx);

typedef struct _HookInfo { 
	char *Module;
	char *Name; 
	ULONG64 Flags; 
	ULONG64 RIP; 
	ULONG64 RSP; 
	DWORD ArgCnt; 
	DWORD ArgRV; 
	ULONG64 ArgLEN; 
	BYTE* Result; 
	FighterFunc *Custom;
} HookInfo, *PHookInfo;

// Overall Context through the handler
// any state we capture + log + extra 
// emulator, decision logic verbose data
typedef struct _ExecutionBlock {
	DWORD64 BlockFrom;
	DWORD64 TSC;
	ULONG InternalID;
	ULONG TID;
	HANDLE hThr;
	csh handle;
	cs_insn *insn;
	size_t csLen;
	ULONG SEQ;
	ULONG HookCnt; // this should bring us back into 64 bit alignment naturally
	PHookInfo Hooks;
	PEXCEPTION_POINTERS pExeption; // filed out on entry to handler
								   //PCONTEXT pContextRecord;	// secondary context acquired by getthreadcontext
	LPVOID DisabledUntil;
	ULONG64 GapRSP;
} ExecutionBlock, *PExecutionBlock;

bool AmIinThreadTable();
bool InitThreadTable(ULONGLONG EstMaxTID);
bool IsThreadInTable(ULONGLONG tid, bool Inst);
void ExitThreadTable(ULONGLONG tid, bool Inst);
void EnterThreadTable(ULONGLONG tid, bool Inst);

void _DumpContext(PExecutionBlock ExceptionInfo);
void DoRandomTestStuff(ULONG Arg);

ULONG64 inline GetArg(DWORD Cnt, PExecutionBlock pCtx);

#include "GlobLog.h"
#include "Config.h"
#include "BlockFighters.h"
#include "EhTrace.h"