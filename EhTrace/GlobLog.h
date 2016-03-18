#pragma once

typedef struct _EFlags {
	union {
		struct {
			DWORD Carry:1;
			DWORD R1:1;
			DWORD Parity:1;
			DWORD R2:1;
			DWORD Aux:1;
			DWORD R3:1;
			DWORD Zero:1;
			DWORD Sign:1;
			DWORD Trap:1;
			DWORD Interrupt:1;
			DWORD Direction:1;
			DWORD Overflow:1;
			DWORD IOPL:2;
			DWORD Nested:1;
			DWORD R4:1;
			DWORD Resume:1;
			DWORD V8086:1;
			DWORD AlignmentCheck:1;
			DWORD VirtualIntFlag:1;
			DWORD VirtualIntPending:1;
			DWORD ID:1;
		};
		DWORD Synth;
	};
} EFflags, *PEflags;

typedef struct _Step_Event {
	union {
		struct {
			ULONG32 TID;
			ULONG32 eFlags;
		};
		ULONG64 Synth;
	} u;
	ULONG64 RIP;		// we could steal some high bits here
	ULONG64 RSP;		// use this for something ! ;)
	ULONG64 FromRIP;
} Step_Event, *PStep_Event;

typedef struct _Trace_Event
{
	ULONG		Seq;		// also a cookie 0xbadcaffe
	ULONG		Tid;        // Thread ID
	ULONGLONG	Registers[17];

	ULONGLONG PADD[0xE];
	
	//ULONGLONG	BlockEntry;
	//ULONGLONG	Stack[5];
	//ULONGLONG	RV;			// return value
	//ULONGLONG	RetAddr;	// steal high bits?
	//ULONGLONG	FnEntry;	// could actually steal the high bits here
	//ULONG		Seq;
	//char		Name[52];
} Trace_Event, *PTrace_Event;


// Larger sizes here will enable faster execution times ;)
static const int STRACE_LOG_BUFFER_SIZE = (1024*1024);


extern "C" void* SetupLogger(ULONG64 LOG_SIZE);
extern "C" void* ConnectLogBuffer(ULONG64 LOG_SIZE);

extern "C" Trace_Event* Log(PExecutionBlock pEx);
extern "C" void LogRIP(PExecutionBlock pEx);

extern "C" Trace_Event* LogPop();
extern "C" Step_Event*  LogPopIP();
extern "C" PStep_Event LogPopMany(LONG64 *Returned);