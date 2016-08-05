#include "stdafx.h"
/*
// Shane.Macaulay@IOActive.com Copyright (C) 2016
//
//Copyright(C) 2016 Shane Macaulay
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
// Shane.Macaulay@IOActive.com (c) copyright 2014,2015,2016 all rights reserved. GNU GPL License
//
*/

/*
	K2: Blockfighting with a hooker... or so it goes.

	Leverage block stepping to simplify program introspection such that we may analyze
	code coverage and execution in detail.  

	Sort of a self-debugging that is fast and able to operate without any code patches, 
	traditional hooks/detours so that check summing will match as needed.

	In a way feels like code-wars/core-wars in a way.  
	Initial release is targeted towards friendly binaries.
	To the tune of A-Track -- Out The Speakers!
*/
// blockfighting defenses? async code aync completion, defend setthreadcontext, 
// Use page protection to detect/defend execution of code?
// redirect attempts to start new threads to ensure that they 
// start suspended and are able to be tracked before execution
// xsave scanning
// pop/ret
// exception handling
// user callbacks
// - RtlInstallFunctionTableCallback
// - RtlAddFunctionTable 
// *callbacks
// threads & fiber create


LONG WINAPI BossLevel(struct _EXCEPTION_POINTERS *ExceptionInfo);
LONG WINAPI vEhTracer(struct _EXCEPTION_POINTERS *ExceptionInfo);

NtSystemDebugControl loadSystemDebugControl = NULL;

#ifdef ALIB_BUILD 
int ALibMain();
extern "C" FARPROC AMain = (FARPROC)ALibMain;
#endif

BOOL GetTokenPriv(HANDLE hProcess, BOOL bEnable, wchar_t* Name);

// not counting ourselves
size_t KnownThreadCount = 0;
size_t UnTracedThreadCount = 0;
HANDLE hPulseThread;

extern "C" static DWORD NoLogThrId = 0;
extern ExecutionBlock *CtxTable;
extern PConfigContext ConfigMap;

void Fight(PExecutionBlock pCtx);
void InitFighters();

// One time init at runtime per thread we bring into monitoring
PExecutionBlock InitBlock(ULONG ID)
{
	PExecutionBlock pCtx = &CtxTable[ID];

	pCtx->TID = ID;
	pCtx->InternalID = ID;
	pCtx->SEQ = 0;
	pCtx->hThr = INVALID_HANDLE_VALUE;
	pCtx->BlockFrom = 0;

	cs_opt_skipdata skipdata = { "db", };
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &pCtx->handle) != CS_ERR_OK)
		return NULL;

	cs_option(pCtx->handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	cs_option(pCtx->handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(pCtx->handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	cs_option(pCtx->handle, CS_OPT_SKIPDATA_SETUP, (size_t)&skipdata);

	pCtx->insn = cs_malloc(pCtx->handle);
	pCtx->csLen = 32;

	pCtx->Hooks = HooksConfig;
	pCtx->HookCnt = HookCount;

	return pCtx;
}

bool InstallThread(ULONG th32ThreadID, int reason)
{
	PExecutionBlock pCtx = NULL;

	pCtx = InitBlock(th32ThreadID);
	if (pCtx == NULL) {
		wprintf(L"unable to install thread %d (OOM?)\n", th32ThreadID);
		return false;
	}

	KnownThreadCount++;

	// OpenThreads for neighbor threads
	pCtx->hThr = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, th32ThreadID);

	// install branch tracing
	CONTEXT ContextRecord = { 0 };
	ContextRecord.ContextFlags = CONTEXT_ALL;

	wprintf(L"%d) attaching to thread ID: %d in process %d\n", reason, th32ThreadID, GetCurrentProcessId());

	if (!GetThreadContext(pCtx->hThr, &ContextRecord))
		wprintf(L"unable to get context on thread %d\n", th32ThreadID);

	// installed a thread
	EnterThreadTable(th32ThreadID, true);

	ContextRecord.EFlags |= 0x100;	// single step
	ContextRecord.Dr7 |= 0x300;		// setup branch tracing 

	if (!SetThreadContext(pCtx->hThr, &ContextRecord))
		wprintf(L"unable to set context on thread %d\n", th32ThreadID);


	return true;
}

// check modules
PLDR_MODULE FirstModule()
{
	static int LastModListCnt;

	// PEB @ 0x60 ? 
	PLDR_MODULE *TEB = (PLDR_MODULE *)__readgsqword(0x60); // + 
	PLDR_MODULE pMod = TEB[0x10];
	return (PLDR_MODULE ) pMod->InInitializationOrderModuleList.Flink;
}

// check all threads to make sure we are installed/configured
// possibly dump stack and make sure this module is in the stack 
void PulseThreads()
{
	DWORD thisPID = GetCurrentProcessId();
	DWORD thisTID = GetCurrentThreadId(); //__readgsdword(0x48);
/*
	PLDR_MODULE first = FirstModule();
	while (first->BaseAddress) {
		printf("Module [%S] loaded at [%p] with entrypoint at [%p]\n", first->BaseDllName.Buffer, first->BaseAddress, first->EntryPoint);
		first = (PLDR_MODULE)first->InMemoryOrderModuleList.Flink;
	}
*/

	while (true)
	{
		Sleep(100);

		HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hTool32 != INVALID_HANDLE_VALUE) {
			THREADENTRY32 thread_entry32;
			thread_entry32.dwSize = sizeof(THREADENTRY32);
			if (Thread32First(hTool32, &thread_entry32)) {
				do {
					if (thread_entry32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(thread_entry32.th32OwnerProcessID)
						&& thread_entry32.th32OwnerProcessID == thisPID
						&& thread_entry32.th32ThreadID != thisTID
						&& thread_entry32.th32ThreadID != NoLogThrId)
					{
						if (!IsThreadInTable(thread_entry32.th32ThreadID, true))
							InstallThread(thread_entry32.th32ThreadID, 1);
					}
				} while (Thread32Next(hTool32, &thread_entry32));
			}
			CloseHandle(hTool32);
		}
	}
}

int Initalize(PVECTORED_EXCEPTION_HANDLER Eh)
{
	if (!InitThreadTable(1000 * 1000))
		wprintf(L"unable to initialize thread tables\n");

	// if debug MSR is available configure it 
	// This may be only required for legacy / cloud / hypervisor guest type environments
	// unfortunately at the moment some hypervisors do poorly when this call is made
	// HyperV does OK, VMWare does seemingly not as OK
	// others not tested
	if (loadSystemDebugControl != NULL)
	{
		if (!GetTokenPriv(GetCurrentProcess(), true, SE_DEBUG_NAME))
			wprintf(L"Unable to get the debug token privilege enabled, functionality will be diminished if required...");

		DWORD Retlen;
		// debug control for branch debugging
		SYSDBG_MSR msr;
		msr.MSR_Address = 0x1D9;
		msr.DATA = 2;
	
		NTSTATUS status = loadSystemDebugControl(DebugSysWriteMsr, &msr, sizeof(SYSDBG_MSR), 0, 0, &Retlen);
		
		// I guess restore things or I should of checked the original state right? :)
		// GetTokenPriv(GetCurrentProcess(), false, SE_DEBUG_NAME);
	}
	// get statics setup
	InitFighters();
	// pull static hook struct into master record for this slot

	// use old school ToolHelp to enum threads
	// count how many threads with this super beast of an API
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hTool32 != INVALID_HANDLE_VALUE) {
		THREADENTRY32 thread_entry32;
		thread_entry32.dwSize = sizeof(THREADENTRY32);
		if (Thread32First(hTool32, &thread_entry32)) {
			do {
				if (thread_entry32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID)
					+ sizeof(thread_entry32.th32OwnerProcessID)
					&& thread_entry32.th32OwnerProcessID == GetCurrentProcessId()
					&& thread_entry32.th32ThreadID != GetCurrentThreadId()) {

					InstallThread(thread_entry32.th32ThreadID, 2);
				}
			} while (Thread32Next(hTool32, &thread_entry32));
		}
		CloseHandle(hTool32);
	}

	// insurance in case the VEH get's toasted
	//SetUnhandledExceptionFilter(&BossLevel);
	if (!AddVectoredExceptionHandler(1, Eh != NULL ? Eh : (PVECTORED_EXCEPTION_HANDLER)vEhTracer)) {
		wprintf(L"unable to install VEH handler\n");
		return -4;
	}
	else
		wprintf(L"installed VEH handler\n");

	return 0;
}

void _DumpEFlags(_EFlags efl)
{
	if(efl.Carry) 
		wprintf(L" Carry ");
	if(efl.Parity)
		wprintf(L" Parity ");
	if (efl.Aux)
		wprintf(L" Aux ");
	if (efl.Zero)
		wprintf(L" Zero ");
	if (efl.Sign)
		wprintf(L" Sign ");
	if (efl.Trap)
		wprintf(L" Trap ");
	if (efl.Interrupt)
		wprintf(L" Interrupt ");
	if (efl.Direction)
		wprintf(L" Direction ");
	if (efl.Overflow)
		wprintf(L" Overflow ");
	if (efl.IOPL)
		wprintf(L" IOPL %d ", efl.IOPL);
	if (efl.Nested)
		wprintf(L" Nested ");
	if (efl.Resume)
		wprintf(L" Resume ");
	if (efl.V8086)
		wprintf(L" V8086 ");
	if (efl.AlignmentCheck)
		wprintf(L" AlignmentCheck ");
	if (efl.VirtualIntFlag)
		wprintf(L" VirtualIntFlag ");
	if (efl.VirtualIntPending)
		wprintf(L" VirtualIntPending ");
	if (efl.ID)
		wprintf(L" ID ");

	wprintf(L"\n");

}

void _DumpContext(PExecutionBlock pXblock)
{
	PCONTEXT pCtx = pXblock->pExeption->ContextRecord;

	DWORD64 csRVA = pCtx->Rip;
	const uint8_t *csLocation = (const uint8_t *)csRVA;
	_EFlags efl;

	efl.Synth = pCtx->EFlags;

	// TODO: insn needs to be thread specific
	if (csRVA && pXblock && cs_disasm_iter(pXblock->handle, &csLocation, &pXblock->csLen, &csRVA, pXblock->insn))
	{
		printf("\n%s %s   | Rip 0x%.16llx (RipFrom 0x%.16llx) EFlags 0x%.8x ", pXblock->insn->mnemonic, pXblock->insn->op_str, pCtx->Rip, pXblock->BlockFrom, pCtx->EFlags);
		_DumpEFlags(efl);
		wprintf(L"\t\t Rax 0x%.16llx, Rcx 0x%.16llx, Rdx 0x%.16llx, Rbx 0x%.16llx\n", pCtx->Rax, pCtx->Rcx, pCtx->Rdx, pCtx->Rbx);
		wprintf(L"\t\t Rsp 0x%.16llx, Rbp 0x%.16llx, Rsi 0x%.16llx, Rdi 0x%.16llx\n", pCtx->Rsp, pCtx->Rbp, pCtx->Rsi, pCtx->Rdi);
		wprintf(L"\t\t R8  0x%.16llx, R9  0x%.16llx, R10 0x%.16llx, R11 0x%.16llx\n", pCtx->R8, pCtx->R9, pCtx->R10, pCtx->R11);
		wprintf(L"\t\t R12 0x%.16llx, R13 0x%.16llx, R14 0x%.16llx, R15 0x%.16llx\n", pCtx->R12, pCtx->R13, pCtx->R14, pCtx->R15);

	}
	// just branch/single step him
	// I'm in the same thread so this isn't that bad
	//EmulateOp(ExceptionInfo);
	// capstone!!
	pXblock->csLen = 32;
}
/*
	 Not really seeing the case for symbol processing in our perf critical loop
int NativeSymbolCompare(const void *node1, const void *node2)
{
	return ((const PNativeSymbol)node1)->Address == ((const PNativeSymbol)node2)->Address ? 0 : -1;
}

/*
Putting this stuff on hold for a bit waiting for open implementation of symbol parsing to mature or just stick to post processing symbols...
PNativeSymbol pSym = (PNativeSymbol)bsearch((void *)(&ExceptionInfo->ContextRecord->Rip),(void *)ConfigMap->SymTab, ConfigMap->SymCnt, sizeof(NativeSymbol), NativeSymbolCompare);
if (pSym == NULL)
{
ExitThreadTable(dwThr, false);
return EXCEPTION_CONTINUE_SEARCH;
}
*/


//ULONG64 GDIPLUS_START2, GDIPLUS_END2;


// In the spirt of so many exceptions! =D blah! https://msdn.microsoft.com/en-us/library/1eyas8tf.aspx
LONG WINAPI vEhTracer(PEXCEPTION_POINTERS ExceptionInfo)
{
	DWORD OldPerm;
	PExecutionBlock pCtx = NULL;

	ULONG64 dwThr = __readgsdword(0x48);


	// TODO: just put the whole context in the array to remove an indirect anyhow
	if (CtxTable != NULL && CtxTable[dwThr].TID != 0)
		pCtx = &CtxTable[dwThr];
	else
		pCtx = InitBlock(dwThr);

	// allow exec
	//pCtx->DisabledUntil = (LPVOID)((ULONG64) ExceptionInfo->ExceptionRecord->ExceptionAddress & ~0x4095);
	
	pCtx->pExeption = ExceptionInfo;
	pCtx->TSC = __rdtsc();

	// check if my thread is a thread that's already entered into the VEH logging something lower on the stack
	// this means were probably getting an exception for something we did ourselves during the logging 
	// which is sort of pointless
	// we could test all Exception address against known entries we provide
	if (AmIinThreadTable())
		return EXCEPTION_CONTINUE_EXECUTION;


	if (ExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
		return EXCEPTION_CONTINUE_SEARCH;

	// no re-entrance while servicing exceptions
	EnterThreadTable(dwThr, false);

	// since we like to do logging
	//LogRIP(pCtx);
	// to dump info 
	//_DumpContext(pCtx);

	// Loop through all of the block fighters
	Fight(pCtx);

	// Thanks Feryno
	// http://x86asm.net/articles/backdoor-support-for-control-transfer-breakpoint-features/
	// 
	ExceptionInfo->ContextRecord->EFlags |= 0x100; // single step
	ExceptionInfo->ContextRecord->Dr7 |= 0x300; // setup branch tracing 

	// record keeping
	pCtx->BlockFrom = ExceptionInfo->ContextRecord->Rip;

	// exit lock
	ExitThreadTable(dwThr, false);
	
	return EXCEPTION_CONTINUE_EXECUTION;
}

// VEH should always allow for us not to worry about this guy?
LONG WINAPI BossLevel(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	wprintf(L"\nTop level: ");
	//_DumpContext(ExceptionInfo);
	return EXCEPTION_CONTINUE_EXECUTION;
}


#ifdef ALIB_BUILD 
int ADllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
#else
__declspec(dllexport) int APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
#endif

{
	unsigned long TID = __readgsdword(0x48);

	if (loadSystemDebugControl == NULL)
	{
		HMODULE dNTdll = GetModuleHandleA("ntdll.dll");
		loadSystemDebugControl = (NtSystemDebugControl)GetProcAddress(dNTdll, "NtSystemDebugControl");
	}

	if (reason == DLL_PROCESS_ATTACH)
	{
		if (AllocConsole()) {
			freopen("CONOUT$", "w", stdout);
			SetConsoleTitle(L"EhTrace Debug Window");
			wprintf(L"DLL loaded.\n");
			if (loadSystemDebugControl != NULL)
				wprintf(L"also ready for DEBUG MSR WRITE");
		}
		ConfigMap = ConnectConfig();
		wprintf(L"Connecting ConfigMap %p\n", ConfigMap);

		// logger will spin the thread if logs are not picked up fast enough
		SetupLogger(STRACE_LOG_BUFFER_SIZE);
		Initalize(NULL);

		InstallThread(TID, 2);
		//hPulseThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PulseThreads, 0, 0, NULL);
		//NoLogThrId = GetThreadId(hPulseThread);

		//wprintf(L"Symbol count is %llx\n", ConfigMap->SymCnt);
		//ConnectSymbols(ConfigMap->SymCnt);

	}
	else if (reason == DLL_THREAD_ATTACH)
	{
		// setup monitoring of this thread
		UnTracedThreadCount++;
		InstallThread(TID, 3);
	}
	else if (reason == DLL_THREAD_DETACH)
	{
		ExitThreadTable(TID, true);
		
		if(CtxTable[TID].insn != NULL)
			cs_free(CtxTable[TID].insn, 1);

		memset(&CtxTable[TID], 0, sizeof(ExecutionBlock));
		wprintf(L"Cleaned up thread %d\n", TID);

	}
	wprintf(L"done in dllmain\n");
	return TRUE;
}

// TODO: Block/Verify attempts to modify VEH list
// testing against our self
#ifdef ALIB_BUILD 
int ALibMain()
#else
int main()
#endif
{
	SetupLogger(STRACE_LOG_BUFFER_SIZE);
	//NoLogThrId = GetCurrentThreadId();

	HMODULE dNTdll = GetModuleHandleA("ntdll.dll");
	loadSystemDebugControl = (NtSystemDebugControl)GetProcAddress(dNTdll, "NtSystemDebugControl");
	if (loadSystemDebugControl == NULL)
		wprintf(L"Not using NtSystemDebugControl\n");

	if (Initalize(vEhTracer))
		wprintf(L"Initialize failed\n");
#ifdef ALIB_BUILD
	printf("installing on current thread\n");
	// this is since were a static lib attach
	InstallThread(GetCurrentThreadId(), 9);
	return 0;
#endif

	HANDLE hTestThr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DoRandomTestStuff, 0, CREATE_SUSPENDED, NULL);

	InstallThread(GetThreadId(hTestThr), 4);
	ResumeThread(hTestThr);

	//wprintf(L"hit a key to start dumping logs");
#if STANDALONE_APREP
	Step_Event* se;
	while (true)
	{
		se = LogPopIP();
		if(se != NULL && se->RIP != 0)
		{
			// major slowdown if we do this ;)
#if FALSE
			wprintf(L"tid [%d] flags[%x] rip[%llx]\n", se->u.TID, se->u.eFlags, se->RIP);
#endif
			se->RIP = 0;
			se->u.Synth = 0;
			se = NULL;
		}
		Sleep(0);
	}
#endif
	Sleep(-1);
	return 0;
}
