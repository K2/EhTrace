// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define ALIB_BUILD

#define _CRT_SECURE_NO_WARNINGS 
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <vector>

#include <Shellapi.h>

#include <TlHelp32.h>

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

typedef CONST char *PCSZ;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING* PCOEM_STRING;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	HMODULE                 BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;

} LDR_MODULE, *PLDR_MODULE;

extern "C" PLDR_MODULE FirstModule();

#include "AEh.h"

/*
DynamoRIO utility macros. Copied from the DyanmoRIO project,
http://dynamorio.org/
*/


#define CLIENTS_COMMON_UTILS_H_



#ifdef DEBUG
# define ASSERT(x, msg) DR_ASSERT_MSG(x, msg)
# define IF_DEBUG(x) x
#else
# define ASSERT(x, msg) /* nothing */
# define IF_DEBUG(x) /* nothing */
#endif

/* XXX: should be moved to DR API headers? */
#define BUFFER_SIZE_BYTES(buf)      sizeof(buf)
#define BUFFER_SIZE_ELEMENTS(buf)   (BUFFER_SIZE_BYTES(buf) / sizeof((buf)[0]))
#define BUFFER_LAST_ELEMENT(buf)    (buf)[BUFFER_SIZE_ELEMENTS(buf) - 1]
#define NULL_TERMINATE_BUFFER(buf)  BUFFER_LAST_ELEMENT(buf) = 0
#define ALIGNED(x, alignment) ((((ptr_uint_t)x) & ((alignment)-1)) == 0)
#define TESTANY(mask, var) (((mask) & (var)) != 0)
#define TEST  TESTANY

#ifdef WINDOWS
# define IF_WINDOWS(x) x
# define IF_UNIX_ELSE(x,y) y
#else
# define IF_WINDOWS(x)
# define IF_UNIX_ELSE(x,y) x
#endif

/* Checks for both debug and release builds: */
#define USAGE_CHECK(x, msg) DR_ASSERT_MSG(x, msg)

static inline generic_func_t
cast_to_func(void *p)
{
#ifdef WINDOWS
#  pragma warning(push)
#  pragma warning(disable : 4055)
#endif
	return (generic_func_t)p;
#ifdef WINDOWS
#  pragma warning(pop)
#endif
}



//#include "limits.h"
//
//// Replace Dr.*
//
//#include "modules.h"
//#include "utils.h"
//
//
//#include "Config.h"





typedef struct _HookInfo {
	char *Name;
	ULONG64 Flags;
	ULONG64 RIP;
	ULONG64 RSP;
	DWORD ArgCnt;
	DWORD ArgRV;
	ULONG64 ArgLEN;
	BYTE* Result;
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
	ULONG64 handle;
	ULONG64 *insn;
	size_t csLen;
	ULONG SEQ;
	ULONG HookCnt; // this should bring us back into 64 bit alignment naturally
	PHookInfo Hooks;
	PEXCEPTION_POINTERS pExeption; // filed out on entry to handler
								   //PCONTEXT pContextRecord;	// secondary context acquired by getthreadcontext
} ExecutionBlock, *PExecutionBlock;
