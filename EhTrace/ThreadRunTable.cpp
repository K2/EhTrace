#include "stdafx.h"

//SRWLOCK ThrLock;
//blah just use a table, back to STL hash later or something
PExecutionBlock CtxTable;
ULONGLONG *ThrInstTable;
ULONGLONG *ThrTable;
ULONGLONG BitsInSet;

// Should really just use a bitmap for this
bool InitThreadTable(ULONGLONG Cnt)
{
	BitsInSet = Cnt;
	ThrTable = (ULONGLONG *) malloc((Cnt >> WORD_BIT_SHIFT) * sizeof(ULONGLONG));
	if (!ThrTable)
		return false;

	BitsInSet = Cnt;
	ThrInstTable = (ULONGLONG *)malloc((Cnt >> WORD_BIT_SHIFT) * sizeof(ULONGLONG));
	if (!ThrInstTable)
	{
		free(ThrTable);
		return false;
	}

	// just load everything into 1 giant array
	CtxTable = (ExecutionBlock *)malloc(Cnt * sizeof(ExecutionBlock));
	if (!CtxTable)
	{
		free(ThrInstTable);
		free(ThrTable);
		return false;
	}

	memset(ThrTable, 0, (Cnt >> WORD_BIT_SHIFT) * sizeof(ULONGLONG));
	memset(ThrInstTable, 0, (Cnt >> WORD_BIT_SHIFT) * sizeof(ULONGLONG));
	memset(CtxTable, 0, Cnt * sizeof(ExecutionBlock));
	return true;
}


void EnterThreadTable(ULONGLONG bit, bool Install)
{
	if(Install)
		ThrInstTable[(bit >> WORD_BIT_SHIFT)] |= (1ull << (bit & WORD_MOD_SIZE));
	else
		ThrTable[(bit >> WORD_BIT_SHIFT)] |= (1ull << (bit & WORD_MOD_SIZE));

	//_interlockedbittestandset64_HLEAcquire((LONGLONG *)&ThrTable[(bit >> WORD_BIT_SHIFT)], 1 << (bit & WORD_MOD_SIZE));
}

// were done processing exception
void ExitThreadTable(ULONGLONG bit, bool Uninstall)
{
	if(Uninstall)
		ThrInstTable[(bit >> WORD_BIT_SHIFT)] &= (~(1ull << (bit & WORD_MOD_SIZE)));
	else
		ThrTable[(bit >> WORD_BIT_SHIFT)] &= (~(1ull << (bit & WORD_MOD_SIZE)));

	//_interlockedbittestandreset64_HLERelease((LONGLONG *)&ThrTable[(bit >> WORD_BIT_SHIFT)], 1 << (bit & WORD_MOD_SIZE));
}

// Check if we are already in the table of exception busy threads
// i.e. we have a stack frame that's already emitting a lot 
// we should see about handling this better, not awesome perf
bool IsThreadInTable(ULONGLONG bit, bool CheckInstallTable)
{
	if(CheckInstallTable)
		return (ThrInstTable[(bit >> WORD_BIT_SHIFT)] & (1ull << (bit & WORD_MOD_SIZE)));

	return (ThrTable[(bit >> WORD_BIT_SHIFT)] & (1ull << (bit & WORD_MOD_SIZE)));
}


bool AmIinThreadTable()
{
	return (ThrTable[(__readgsdword(0x48) >> WORD_BIT_SHIFT)] & (1ull << (__readgsdword(0x48) & WORD_MOD_SIZE)));
}