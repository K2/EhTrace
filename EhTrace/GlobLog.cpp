#include "stdafx.h"

#define BUFF_PADD 0x10
Step_Event  *g_stepev = NULL;
ULONG64 THE_LOG_SIZE = 0;
ULONG64 THE_LOG_COUNT = 0;
ULONG64 THE_EIP_LOG_COUNT = 0;


volatile LONG64 *Lock;
volatile ULONG64 *g_WriteIdx;
volatile ULONG64 *g_WaitingRecords;
volatile ULONG64 *Seq;
volatile ULONG64 *g_ReadIdx;

PTrace_Event ShareMap;
Trace_Event *g_events = NULL;
ULONG64 *HDR;

extern "C" void *SetupLogger(ULONG64 LOG_SIZE)
{
	if (LOG_SIZE < STRACE_LOG_BUFFER_SIZE)
		LOG_SIZE = STRACE_LOG_BUFFER_SIZE;

	THE_LOG_SIZE = LOG_SIZE; //pad out to avoid any possible issues on the last page
	THE_LOG_COUNT = LOG_SIZE / sizeof(Trace_Event);
	THE_EIP_LOG_COUNT = LOG_SIZE / sizeof(Step_Event);

	ULONG64 PaddedSize = THE_LOG_SIZE + 65536;

	// Global\EhTraceStep will be step logs
	// Global\EhTrace full contexts
	HANDLE hGlobMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, PaddedSize >> 32, PaddedSize & 0xffffffff, L"EhTraceStep");
	if (hGlobMap == INVALID_HANDLE_VALUE)
	{
		wprintf(L"can not map memory %d", GetLastError());
		exit(-1);
	}

	ShareMap =  (PTrace_Event)  MapViewOfFile(hGlobMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (!ShareMap)
	{
		wprintf(L"unable to map shared log data %d", GetLastError());
		if(g_WaitingRecords != NULL)
			*g_WaitingRecords = -1; // signal to pick up the pace on the reader side
		exit(-2);
	}
	wprintf(L"log buffer is @ %p\n", ShareMap);

	HDR = (ULONG64*) ShareMap;

	Seq = HDR++;
	g_WriteIdx = HDR++;
	g_ReadIdx = HDR++;
	g_WaitingRecords = HDR++;
	Lock = (LONG64 *) HDR++;
	HDR++;

	g_stepev = (Step_Event *) HDR;
	g_events = (PTrace_Event) HDR;

	*Seq = 0;
	*g_WriteIdx = BUFF_PADD;  // start things off @ -1 InterlockedInc gives us back the post-added size so to get zero indexed we start here @-1
	*g_ReadIdx = BUFF_PADD;
	*g_WaitingRecords = 0;
	*Lock = 0;

	return (void *) ShareMap;
}

extern "C" void *ConnectLogBuffer(ULONG64 LOG_SIZE)
{
	THE_LOG_SIZE = LOG_SIZE; //pad out to avoid any possible issues on the last page
	THE_LOG_COUNT = LOG_SIZE / sizeof(Trace_Event);
	THE_EIP_LOG_COUNT = LOG_SIZE / sizeof(Step_Event);

	HANDLE hGlobMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, LOG_SIZE >> 32, LOG_SIZE & 0xffffffff, L"EhTraceStep");

	ShareMap = (PTrace_Event)MapViewOfFile(hGlobMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (!ShareMap)
	{
		wprintf(L"unable to map shared log data");
		return NULL;
	}
	wprintf(L"log buffer is @ %p\n", ShareMap);
	HDR = (ULONG64*)ShareMap;

	Seq = HDR++;
	g_WriteIdx = HDR++;
	g_ReadIdx = HDR++;
	g_WaitingRecords = HDR++;
	Lock = (LONG64 *) HDR++;
	HDR++;

	g_events = (PTrace_Event)HDR;
	g_stepev = (PStep_Event)HDR;

	wprintf(L"Ready Events = %llx\n", *g_WaitingRecords);
	return ShareMap;
}

LONG64 Zero = 0;

extern "C" void LogRIP(PExecutionBlock pEx)
{
	if (g_events == NULL)
		return;
	while (*g_WaitingRecords > THE_EIP_LOG_COUNT - BUFF_PADD) {
		//wprintf(L"pre stall\n");
		Sleep(100);
	}
	
	Step_Event se;
	se.u.TID = __readgsdword(0x48);
	se.u.eFlags = pEx->pExeption->ContextRecord->EFlags;
	se.RIP = pEx->pExeption->ContextRecord->Rip;
	se.FromRIP = pEx->BlockFrom;	
	se.RSP = pEx->pExeption->ContextRecord->Rsp;

	//LONG64 index = InterlockedAdd64((volatile long long *)g_WriteIdx, 2);
	ULONG64 index = InterlockedIncrement64((volatile long long *)g_WriteIdx);

	// move past any of the header meta info
	if (index >= THE_EIP_LOG_COUNT - BUFF_PADD)
		index = *g_WriteIdx = BUFF_PADD;

	PStep_Event curr = &g_stepev[index];

	// we wait here for the log slot to become available in the ring buffer
	// if the consumer isn't clearing this out fast enough, we wind up blocking the thread
	while (InterlockedCompareExchange128((LONG64*)curr,
		(ULONG64)se.RIP, (ULONG64)se.u.Synth, &Zero) == 0)
	{ 
		if (Zero != 0)
			Zero = 0;
	}
	// if were here we won the slot so it should be available to just write
	curr->FromRIP = se.FromRIP;
	curr->RSP = se.RSP;

	InterlockedIncrement64((volatile long long *)g_WaitingRecords);
}

// After popping off the event data
// you need to manually zero out the record
// or else the producer log function will block the
// process which has the inserted ehtrace.dll
extern "C"  PStep_Event LogPopIP()
{
	PStep_Event rv = NULL;

	while (*g_WaitingRecords == 0)
		YieldProcessor;

	ULONG64 index = InterlockedIncrement64((volatile long long *)g_ReadIdx);

	// move past any of the header meta info
	if (index >= THE_EIP_LOG_COUNT - BUFF_PADD)
		index = *g_ReadIdx = BUFF_PADD;

	// BUGBUG: fixup locking when we get logmany working!
	//while (InterlockedCompareExchangeAcquire64(Lock, 1, 0) != 0);
	InterlockedDecrement64((volatile long long *)g_WaitingRecords);
	//InterlockedCompareExchangeRelease64(Lock, 0, 1);

	rv = &g_stepev[index];
	return rv;
}


extern "C" PStep_Event LogPopMany(LONG64 *Returned)
{
	PStep_Event rv = NULL;

	while (InterlockedCompareExchangeAcquire64(Lock, 1, 0) != 0);

	LONG64 ReadIndex = *g_ReadIdx;
	LONG64 CurrCnt = *g_WaitingRecords;
	// can we take a chunk less than the ring overflow size
	if (CurrCnt + ReadIndex < (THE_EIP_LOG_COUNT - BUFF_PADD))
	{
		do { CurrCnt = InterlockedCompareExchange64((LONG64*)g_WaitingRecords, 0, CurrCnt); } while (CurrCnt != 0);
		CurrCnt = ReadIndex - BUFF_PADD + 1;
	}
	else // take a smaller chunk
	{
		CurrCnt = THE_EIP_LOG_COUNT - BUFF_PADD - ReadIndex;
		// converted all loggers to use Lock so maybe we don't need as many interlocked on the access for this one
		*g_WaitingRecords -= CurrCnt;
	}

	InterlockedCompareExchangeRelease64(Lock, 0, 1);
	rv = &g_stepev[ReadIndex];
	*Returned = CurrCnt;
	return rv;

}


// Every thread comes in here to log simultaneously
// we have a wait free lock I guess in a simple index
// until we implement something like a log-bitmap that
// configures who to log, we'll just log it all to test
// our limits
extern "C" Trace_Event* Log(PExecutionBlock pEx)
{
	if (g_events == NULL)
		return NULL;

	while (*g_WaitingRecords > THE_LOG_COUNT - 2) {
		//wprintf(L"pre stall\n");
		Sleep(100);
	}

	// Get next event index
	ULONG64 index = _InterlockedIncrement64((volatile long long *)g_WriteIdx);
	//wprintf(L"writing to slot 0x%x\n", index);
	while (index > THE_LOG_COUNT-BUFF_PADD)
	{
		if (*g_WaitingRecords == 0)
			index = *g_WriteIdx = BUFF_PADD;
		else if (*g_WaitingRecords >= THE_LOG_COUNT-BUFF_PADD)
		{
			// we cant hold any more logs
			// nobody has picked them up yet or we haven't
			// found a way to dump them to disk
			// so just stop here instead of wrapping
			//wprintf(L"write stalling\n");
			Sleep(100);
		}
		else
			Sleep(1);
	}
	// were committed to get an entry logged 
	// global seq
	_InterlockedIncrement64((volatile long long *)Seq);

	// Write an event at this index (index & (THE_LOG_COUNT - 1)) makes the bitwise work to wrap index +1 is so we don't trash the header so long as header <= sizeof(EVENT)
	Trace_Event* e = g_events + index;  // Wrap to buffer size

	e->Seq = (ULONG)*Seq;
	e->Tid = __readgsdword(0x48);					// Get thread ID

	memcpy(e->Registers, (LPVOID) ((BYTE *)pEx->pExeption->ContextRecord + offsetof(struct _CONTEXT, Rax)), sizeof(e->Registers));

	_InterlockedIncrement64((volatile long long *)g_WaitingRecords);

	return e;
}

extern "C" Trace_Event* LogPop()
{
	if (*g_WaitingRecords == 0)
		return NULL;

	LONG64 index = _InterlockedIncrement64((volatile long long *)g_ReadIdx);
	if (index == THE_LOG_COUNT-BUFF_PADD)
		index = *g_ReadIdx = BUFF_PADD;
	
	_InterlockedDecrement64((volatile long long *)g_WaitingRecords);
	
	return &g_events[index];
	//memcpy(pEv, g_events + index, sizeof(Trace_Event));
	//return sizeof(Trace_Event);
}