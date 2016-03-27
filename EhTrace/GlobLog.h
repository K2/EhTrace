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

// currently 32 bytes
// gettsc into the reserved bit's for time of execution
typedef struct _Step_Event {
	union {
		struct {
			ULONG32 TscA : 16;
			ULONG32 TID : 16;   // upper 16 used for tsc
			ULONG32 eFlags;  // some reserved bits here but let's just leave them alone for now
		};
		ULONG64 Synth;
	} u;
	ULONG64 TscB : 16;
	ULONG64 RIP : 48;		// we could steal some high bits here	
	ULONG64 TscC : 16;
	ULONG64 RSP : 48;		// use this for something ! ;)			
	ULONG64 TscD : 16;											
	ULONG64 FromRIP : 48;
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

static const int STRACE_LOG_BUFFER_SIZE = (sizeof(Step_Event) * 1024*1024*32);

extern "C" void* SetupLogger(ULONG64 LOG_SIZE);
extern "C" void* ConnectLogBuffer(ULONG64 LOG_SIZE);

extern "C" Trace_Event* Log(PExecutionBlock pEx);
extern "C" void LogRIP(PExecutionBlock pEx);

extern "C" Trace_Event* LogPop();
extern "C" Step_Event*  LogPopIP();
extern "C" PStep_Event LogPopMany(LONG64 *Returned);