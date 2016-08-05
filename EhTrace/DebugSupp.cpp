 #include "stdafx.h"

/*

	Random debug/attempts to execute various stuff

*/

#pragma intrinsic(_ReturnAddress, _xsaveopt64)

extern cs_insn *insn;

typedef NTSYSCALLAPI NTSTATUS(NTAPI *NtContinue)(_In_ PCONTEXT Context, _In_ BOOLEAN TestAlert);
typedef NTSYSCALLAPI NTSTATUS(NTAPI *_2ArgFn)(ULONG64 A1, ULONG64 A2);
DWORD64 *ThrStack = NULL;
LPVOID SStack;

//extern __declspec(dllimport) int fnTestSupMod(void);


BOOL GetTokenPriv(HANDLE hProcess, BOOL bEnable, wchar_t* Name)
{
	struct {
		DWORD Count;
		LUID_AND_ATTRIBUTES Privilege[1];
	} Info;

	HANDLE Token;
	BOOL Result;

	// Open the token.
	Result = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &Token);

	if (Result != TRUE)
	{
		wprintf(L"Cannot open process token.\n");
		return FALSE;
	}

	// Enable or disable?
	Info.Count = 1;
	if (bEnable)
		Info.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		Info.Privilege[0].Attributes = 0;

	// Get the LUID.
	Result = LookupPrivilegeValue(NULL, Name, &(Info.Privilege[0].Luid));
	if (Result != TRUE)
	{
		wprintf(L"Cannot get privilege for %s.\n", Name);
		return FALSE;
	}

	// Adjust the privilege.
	Result = AdjustTokenPrivileges(Token, FALSE, (PTOKEN_PRIVILEGES)&Info, 0, NULL, NULL);
	if (Result != TRUE)
	{
		wprintf(L"Cannot adjust token privileges (%u)\n", GetLastError());
		return FALSE;
	}
	else
	{
		if (GetLastError() != ERROR_SUCCESS)
		{
			wprintf(L"Cannot enable the %s privilege; ", Name);
			wprintf(L"please check the local policy.\n");
			return FALSE;
		}
	}

	CloseHandle(Token);
	return TRUE;
}

bool WINAPI f0(void)
{
	return wprintf(L"f0\n") > 1 ? true : false;
}

void WINAPI f1(DWORD a)
{
	wprintf(L"f1: a=%d\n", a);
}

void WINAPI f2(int a, int b)
{
	wprintf(L"f2: a=%d b=%d\n", a, b);
}

ULONGLONG WINAPI f3(int a, int b, void *c)
{
	// use nothing
	return f0();
	//wprintf(L"f3: a=%d b=%d c=%d\n", a, b, c);
}

void WINAPI f4(DWORD *a, int b, int c, int d)
{
	// we only use A & C
	f3(*a, c, a);
	wprintf(L"f4: a=%p c=%d\n", a, c);
}

void * WINAPI f5(int a, DWORD b, int c, DWORD *d, ULONGLONG e)
{
	f4(d, b, a, c);
	wprintf(L"f5: a=%d b=%d c=%d d=%p e=%llx\n", a, b, c, d, (unsigned __int64)e);
	return d;
}

int WINAPI f6(int a, ULONGLONG b, int c, ULONG_PTR d, ULONG_PTR e, ULONG_PTR f)
{
	f5(0, b&0xffffffff, c, (DWORD *)&d, f);
	return wprintf(L"f6: a=%d b=%llx c=%d d=%llx e=%llx f=%llx\n", a, b, c, d, e, f);
}

char WINAPI f7(ULONGLONG a, int b, int c, ULONG d, int e, ULONG_PTR f, int g)
{
	wprintf(L"f7: a=%llx b=%d c=%d d=%d e=%d f=%llx g=%d\n", a, b, c, d, e, f, g);
	f6(a & 0xffffffff, b, c, d, e, f);
	char *ptr = 0;
	//*ptr = 0;
	return 'a';
}
void loop()
{
	ULONGLONG ullast = ullast = __rdtsc(), ulcurr = 0, ullStart=0, ullEnd=0;
	DWORD dw1 = 1, dw = 4, dw3 = 3;
	HMODULE loaded = NULL;

	ullStart = __rdtsc();
	for (int i = 0; i < 8; i++)
	{
		f1(1);
		ulcurr = __rdtsc();
		wprintf(L"drift = %I64d\n", ulcurr - ullast);
		ullast = ulcurr;
		f2(1, 2);
		ulcurr = __rdtsc();
		wprintf(L"drift = %I64d\n", ulcurr - ullast);
		ullast = ulcurr;
		f3(1, 2, &dw3);
		ulcurr = __rdtsc();
		wprintf(L"drift = %I64d\n", ulcurr - ullast);
		ullast = ulcurr;
		f4(&dw1, 2, 3, 4);
		ulcurr = __rdtsc();
		wprintf(L"drift = %I64d\n", ulcurr - ullast);
		ullast = ulcurr;
		f5(1, 2, 3, &dw, 5);
		ulcurr = __rdtsc();
		wprintf(L"drift = %I64d\n", ulcurr - ullast);
		ullast = ulcurr;
		f6(1, 2, 3, 4, 5, 6);
		ulcurr = __rdtsc();
		wprintf(L"drift = %I64d\n", ulcurr - ullast);
		ullast = ulcurr;
		f7(1, 2, 3, 4, 5, 6, 7);
		ulcurr = __rdtsc();
		wprintf(L"drift = %I64d\n", ulcurr - ullast);
		ullast = ulcurr;
		wprintf(L"---MAIN LOOP---\n");
	}
	ullEnd = __rdtsc();
	wprintf(L"TSC START [%I64d] END [%I64d] DIFF [%I64d]\n", ullStart, ullEnd, ullEnd - ullStart);
	Sleep(-1);
	return;
}


void DoRandomTestStuff(ULONG Arg)
{
	loop();
}

#ifdef DEBUG_TEST_CASES

// VEH should always allow for us not to worry about this guy?
LONG WINAPI BossLevel(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	wprintf(L"\nTop level: ");
	_DumpContext(ExceptionInfo);
	return EXCEPTION_CONTINUE_EXECUTION;
}

// may be better place to configure DR registers and such
// so the VEH handlers do not mess us up, however
// this adds lag
LONG WINAPI ContHandler1(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	wprintf(L"\nAfter SEH Continue Handler: ");

	DWORD Retlen;
	// debug control for branch debugging
	SYSDBG_MSR msr;
	msr.MSR_Address = 0x1D9;
	msr.DATA = 2;

	_DumpContext(ExceptionInfo);
	ExceptionInfo->ContextRecord->EFlags |= 0x100;
	//ExceptionInfo->ContextRecord->Rip += insn->size;

	NTSTATUS status = loadSystemDebugControl(DebugSysWriteMsr, &msr, sizeof(SYSDBG_MSR), 0, 0, &Retlen);
	return EXCEPTION_CONTINUE_EXECUTION;
}
// signal() didn't work out well 
// nor did termination handlers
PRUNTIME_FUNCTION getFunc(_In_ DWORD64 ControlPc, _In_opt_ PVOID Context)
{
	wprintf(L"here");
	return 0;
}

void __CRTDECL SigMe(int num)
{
	wprintf(L"\n sig handler: ");
	return;
}

// needed to do something like this if we have blown the stack in a stackoverflow exptn
void DumpContext(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	HANDLE hTestThr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)_DumpContext, ExceptionInfo, 0, 0);
}

// find a context for this exception
// should be isolated by thread
//PSLIST_HEADER pListTemp = (PSLIST_HEADER)_alloca(sizeof(SLIST_HEADER));
//InitializeSListHead(pListTemp);
//PExecutionBlock pXblock = NULL;
//do
//{
//	// pop from the primary list
//	pXblock = (PExecutionBlock) InterlockedPopEntrySList(pListHead);
//	if (pXblock != NULL && pXblock->TID == __readgsdword(0x48))
//	{
//		pXblock->pExeption = ExceptionInfo;
//		break;
//	}   

//	InterlockedPushEntrySList(pListTemp, &(pXblock->ItemEntry));

//} while (pXblock != NULL); // if we get here we have no understanding of this thread
// repair our Xblocks
//InterlockedPushListSListEx(pListHead, (PSLIST_ENTRY) pXblock, )

LONG WINAPI FakeHandler(PCONTEXT Context)
{
	//DWORD64 csRVA = Context->Rip;
	//const uint8_t *csLocation = (const uint8_t *)csRVA;
	EXCEPTION_POINTERS ExceptionInfo = { 0 };
	ExceptionInfo.ContextRecord = Context;
	wprintf(L"\nFake: ");
	DumpContext(&ExceptionInfo);
	return EXCEPTION_CONTINUE_EXECUTION;
}

void __cdecl TerminateHandler()
{
	if (!AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VectoredHandler1))
		wprintf(L"unable to install VEH handler\n");
	if (!AddVectoredContinueHandler(1, ContHandler1))
		wprintf(L"unable to install continue handler\n");
	SetUnhandledExceptionFilter(&BossLevel);
}

BOOL GetTokenPriv(HANDLE hProcess, BOOL bEnable)
{
	struct {
		DWORD Count;
		LUID_AND_ATTRIBUTES Privilege[1];
	} Info;

	HANDLE Token;
	BOOL Result;

	// Open the token.

	Result = OpenProcessToken(hProcess,
		TOKEN_ADJUST_PRIVILEGES,
		&Token);

	if (Result != TRUE)
	{
		_tprintf(_T("Cannot open process token.\n"));
		return FALSE;
	}

	// Enable or disable?

	Info.Count = 1;
	if (bEnable)
	{
		Info.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		Info.Privilege[0].Attributes = 0;
	}

	// Get the LUID.

	Result = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &(Info.Privilege[0].Luid));
	if (Result != TRUE)
	{
		_tprintf(_T("Cannot get privilege for %s.\n"), SE_DEBUG_NAME);
		return FALSE;
	}

	// Adjust the privilege.

	Result = AdjustTokenPrivileges(Token, FALSE, (PTOKEN_PRIVILEGES)&Info, 0, NULL, NULL);

	// Check the result.
	if (Result != TRUE)
	{
		_tprintf(_T("Cannot adjust token privileges (%u)\n"), GetLastError());
		return FALSE;
	}
	else
	{
		if (GetLastError() != ERROR_SUCCESS)
		{
			_tprintf(_T("Cannot enable the SE_DEBUG_NAME privilege; "));
			_tprintf(_T("please check the local policy.\n"));
			return FALSE;
		}
	}

	CloseHandle(Token);

	return TRUE;
}

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

// save this for more exotic needs
typedef ULONG(__stdcall *NtSystemDebugControl)(DEBUG_CONTROL_CODE ControlCode, PVOID InputBuffer,
	ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnLength);
NtSystemDebugControl loadSystemDebugControl;

//single step address 0x1D9, data = 2

void AtD(ULONG64 SIG)
{
	// double D level
	ULONG64 Local = 0xDDDDDDDDDDDDDDDD;
	//wprintf(L"I'm Deeezizy %llx @ %p\n", Local, &Local);
}
void AtC(ULONG64 SIG)
{
	ULONG64 Local = 0xCCCCCCCCCCCCCCCC;
	ULONG64 *lp = &Local;

	//wprintf(L"I'm Cheezeie %llx @ %p\n", Local, &Local);
	//wprintf(L"Can I hit B? %llx\n", *(lp+6));

	AtD(0xCDCDCDCD);

	//wprintf(L"Can I hit D? %llx\n", *lp);
	//wprintf(L"Can I hit D? %llx\n", *(lp+1));
	//wprintf(L"Can I hit D? %llx\n", *(lp-5));
	//wprintf(L"Can I hit D? %llx\n", *(lp-6));
	//wprintf(L"Can I hit D? %llx\n", *(lp-7));
	//wprintf(L"Can I hit D? %llx\n", *(lp-8));

}
void AtB(ULONG64 SIG)
{
	ULONG64 Local = 0xBBBBBBBBBBBBBBBB;
	_alloca(0x1000);
	//wprintf(L"I'm Beeezizy %llx @ %p\n", Local, &Local);
	AtC(0xBCBCBCBC);
	//wprintf(L"I'm Beeezizy %llx @ %p\n", Local, &Local);
	char *ptr = 0;
	*ptr = 0;
}
void AtA(ULONG64 SIG)
{
	ULONG64 Local = 0xAAAAAAAAAAAAAAAA;

	// set thread stack for tracking purposes
	ThrStack = &Local;

	while (true)
	{
		//wprintf(L"I'm Aezizy %llx @ %p\n", Local, &Local);
		AtB(0xABABABAB);
		//wprintf(L"I'm Aezizy %llx @ %p\n", Local, &Local);
	}
}

__declspec(noinline) __declspec(safebuffers)
void SlimLog(void *PreviousRA)
{
	// optimize the bitmask last to not worry about restoring the volatile instructions
	//GetThreadContext(GetCurrentThread(), &ctx);

	void *currRA = _AddressOfReturnAddress();
	currRA = PreviousRA;
}

ULONG64 ScanDoubleJmp()
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	ULONG64 rv = 0;
	cs_opt_skipdata skipdata = { "db", };
	unsigned __int64 csRVA = ctx.Rip;
	const uint8_t *csLocation = (const uint8_t *)csRVA; // in proc
	size_t csLength = 0x3000;
	csh handle;
	bool FoundRet = false;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA_SETUP, (size_t)&skipdata);

	cs_insn *insn = cs_malloc(handle);

	bool IsJmp = false, IsIRet = false, IsRet = false, IsPriv = false;
	while (cs_disasm_iter(handle, &csLocation, &csLength, &csRVA, insn) && !FoundRet)
	{
		for (int i = 0; i < insn->detail->groups_count; i++)
		{
		}
	}
}

enum StackOps {
	NONE = 0,		// Not using stack, then why we break?
	PUSH = 1,		// Adjust RSP by word size 8 bytes
	POP = 2,		// ""
	ADD = 4,		// Adjust RSP by register or immediate value 
	SUB = 8,
	CALL = 0x10000,  // these require changes (2 writes) to more than just the RSP
	RET = 0x20000,	// we have to modify RIP also 

	BUGBUG = 0xf0000000
};

FORCEINLINE DWORD64 GetRegValue(PCONTEXT pCtx, x86_reg reg)
{
	switch (reg)
	{
	case X86_REG_RAX: return pCtx->Rax;
	case X86_REG_RCX: return pCtx->Rcx;
	case X86_REG_RDX: return pCtx->Rdx;
	case X86_REG_RBX: return pCtx->Rbx;
	case X86_REG_RBP: return pCtx->Rbp;
	case X86_REG_RSI: return pCtx->Rsi;
	case X86_REG_RDI: return pCtx->Rdi;
	case X86_REG_R8: return pCtx->R8;
	case X86_REG_R9: return pCtx->R9;
	case X86_REG_R10: return pCtx->R10;
	case X86_REG_R11: return pCtx->R11;
	case X86_REG_R12: return pCtx->R12;
	case X86_REG_R13: return pCtx->R13;
	case X86_REG_R14: return pCtx->R14;
	case X86_REG_R15: return pCtx->R15;
	default:return 0;
	}
}
DWORD64 *eStackWritePtr;
void EmulateOp(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	PCONTEXT pCtx = ExceptionInfo->ContextRecord;
	cs_detail *Detail = insn->detail;
	cs_x86 *x86 = &insn->detail->x86;
	StackOps EmuOp = StackOps::NONE;

	if (insn->id == X86_INS_MOV)
	{
		DWORD64 Value = 0;
		DWORD64 *StackWritePtr = eStackWritePtr;;
		// this is likely a save/restore of a non-volatile register
		// make this a MACRO
		// stack is RO so this must be a write into RSP
		// find the reg and make the write, adjust RIP and exit
		for (int i = 0; i < x86->op_count; i++)
		{
			cs_x86_op *op = &(x86->operands[i]);
			if ((int)op->type == X86_OP_IMM)
				Value = op->imm;
			else if ((int)op->type == X86_OP_REG)
				Value = GetRegValue(pCtx, op->reg);
			else // it's mem read into RSP... weird
			{
				// look for RSP target
				if ((op->mem.base == X86_REG_RSP) || (op->mem.index == X86_REG_RSP) || (op->mem.segment == X86_REG_RSP))
				{
					// rsp based address


					// DOUBLE CHECK
					wprintf(L"boo\n");
				}
				else if (op->mem.disp != 0)
					StackWritePtr = (DWORD64 *)op->mem.disp;
			}
		}
		*StackWritePtr = Value;
		pCtx->Rip += insn->size;

	}
	else
		if (insn->id == X86_INS_ADD)
		{
			;
		}
		else
		{
			// I hope there's not tons of redundant groups
			for (int i = 0; i < Detail->groups_count; i++)
			{
				switch (Detail->groups[i]) {
				case CS_GRP_CALL: EmuOp = StackOps::CALL; break;
				case CS_GRP_RET: EmuOp = StackOps::RET; break;
				default: EmuOp = StackOps::BUGBUG; break;
				}
			}

			if ((EmuOp & StackOps::CALL))
			{
				// adjust RIP & RSP 
				// RtlRestoreContext to go out
				DWORD64 NewRIP = 0;
				// resolve jump target
				for (int i = 0; i < x86->op_count; i++)
				{
					cs_x86_op *op = &(x86->operands[i]);
					if ((int)op->type == X86_OP_IMM)
						NewRIP = op->imm;
					else
						NewRIP = insn->address + insn->size + op->mem.disp; // this should be true 
				}
				// also adjust stack
				// in the case of a call, we have a single push, that means RSP-=8
				pCtx->Rsp -= 8;
				pCtx->Rip = NewRIP;
			}

		}
	//RtlRestoreContext(pCtx, ExceptionInfo->ExceptionRecord);
}

void Test1()
{
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	DWORD TID;
	EnterThreadTable(TID);

	GetThreadContext(hTestThr, &ctx);

	DWORD64 TopStackAddr, BaseStackAddr, *SavedRV, TestTop = ~0xffff;
	HMODULE hCurrExe = GetModuleHandle(NULL);

	VirtualQuery((LPVOID)(ctx.Rsp), &mbi, sizeof(mbi));
	size_t siz = ((size_t)mbi.BaseAddress + mbi.RegionSize) - (size_t)mbi.AllocationBase;
	//LPVOID NewStackLim = VirtualAlloc(0, siz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE | PAGE_GUARD);
	LPVOID NewStackLim = VirtualAlloc(0, siz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	ctx.Rsp = ((DWORD64)NewStackLim + siz) - 4096;

	wprintf(L"new stack size 0x%llx  LIM 0x%llx RSP %llx\n", siz, NewStackLim, ctx.Rsp);
	ctx.EFlags |= 0x100;
	SetThreadContext(hTestThr, &ctx);
	DWORD64 *test = (DWORD64 *)((DWORD64)NewStackLim + siz) - 4096;

	eStackWritePtr = (DWORD64 *)VirtualAlloc(0, siz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	ResumeThread(hTestThr);

	// from here out the exception handlers will drive
	while (true)
	{
		Sleep(100);
	}
}


#ifdef FALSE


GetTokenPriv(GetCurrentProcess(), true);

HMODULE dNTdll = GetModuleHandleA("ntdll.dll");
loadSystemDebugControl = (NtSystemDebugControl)GetProcAddress(dNTdll, "NtSystemDebugControl");
if (loadSystemDebugControl == NULL)
{
	wprintf(L"Can't find NtSystemDebugControl :( go write a kernel driver!\n");
	return -2;
}


/*

bool IsJmp = false, IsIRet = false, IsRet = false, IsPriv = false;
while (cs_disasm_iter(handle, &csLocation, &csLength, &csRVA, insn) && !FoundRet)
{
for (int i = 0; i < insn->detail->groups_count; i++)
{
switch (insn->detail->groups[i]) {
case CS_GRP_JUMP: IsJmp = true; break;
case CS_GRP_RET: IsRet = true; break;
case CS_GRP_IRET: IsIRet = true; break;
case CS_GRP_PRIVILEGE: IsPriv = true; break;
default: break;
}

// take false route if we haven't gone that way before
if (IsJmp)
{
}
// keep going don't take the same jump twice, assume false every time to
// hopefully find the error path ;)?
/*for (int i = 0; i < insn->detail->groups_count; i++)
{
switch (insn->detail->groups[i]) {
case CS_GRP_JUMP: IsJmp = true; break;
case CS_GRP_RET: IsRet = true; break;
case CS_GRP_IRET: IsInt = true; break;
case CS_GRP_PRIVILEGE: IsPriv = true; break;
default: break;
}
}
}
return 0;

//rop hook
//figure out stack top
//assign previous rv into stack top
//insert return in to log function
//do whatever logging then replace log fn return addr with saved ret addr
//while(true)
//{
//	//ctx.ContextFlags = CONTEXT_ALL;
//	//GetThreadContext(GetCurrentThread(), &ctx);

//
//
//}
}
*/
//
//try {
//do {
//SavedRV = (DWORD64 *)(ctx.Rsp & TestTop);
//ctx.Rsp += 0x1000;
//} while (*SavedRV);
//}
//catch (...) {
//}
//TopStackAddr = (DWORD64)SavedRV;
//ctx.Rsp -= 0x1000;
//try {
//do {
//ctx.Rsp -= 0x1000;
//SavedRV = (DWORD64 *)(ctx.Rsp & TestTop);
//} while (*SavedRV);
//}
//catch (...) {
//};
//BaseStackAddr = (DWORD64)SavedRV;

// make stack read only
//if (VirtualProtect((LPVOID)BaseStackAddr, TopStackAddr - BaseStackAddr, PAGE_READONLY, &OldProt))
//	wprintf(L"Failed to protect stack range.");
//VirtualProtect((LPVOID)mbi.BaseAddress, mbi.RegionSize, PAGE_NOACCESS, &OldProt);
/*size_t siz = ((size_t)
mbi.BaseAddress + mbi.RegionSize) - (size_t)mbi.AllocationBase;
for (size_t i = (size_t)mbi.BaseAddress; i < siz; i += 4096)
{
if (!VirtualProtect((LPVOID) i, mbi.RegionSize, mbi.AllocationProtect | PAGE_GUARD, &OldProt))
wprintf(L"failed to protect %llx\n", i);
i += 4096;
}*/

//VirtualQuery((LPVOID)(getFunc), &mbi, sizeof(mbi));
//BOOLEAN val = RtlInstallFunctionTableCallback(ctx.Rsp | 0x3,(DWORD64)  mbi.BaseAddress, mbi.RegionSize, &getFunc, NULL, NULL);
//wprintf(L"bool = %x\n", val);

// Continue handler is called after VEH http://www.masmforum.com/board/index.php?topic=16242.0

//if (!AddVectoredContinueHandler(1, ContHandler1))
//	wprintf(L"unable to intall continue handler\n");
//SetUnhandledExceptionFilter(&BossLevel);

//DWORD Retlen;
//// debug control for branch debugging
//SYSDBG_MSR msr;
//msr.MSR_Address = 0x1D9;
//msr.DATA = 2;
//ExceptionInfo->ContextRecord->Rip += insn->size;
//ExceptionInfo->ContextRecord->Dr7 |= 1 << 9; 
//ExceptionInfo->ContextRecord->Dr7 |= 1 << 8;
//NTSTATUS status = loadSystemDebugControl(DebugSysWriteMsr,
//	&msr, sizeof(SYSDBG_MSR), 0, 0, &Retlen);
//TODO: Add logic to remove thread entries

HMODULE hNtDLL = GetModuleHandleA("ntdll.dll");
_2ArgFn NtContinue = (_2ArgFn)GetProcAddress(hNtDLL, "NtContinue");
if (NtContinue == NULL)
{
	wprintf(L"Can not find NtContinue\n");
	return -1;
}

DWORD a_arg = 0x0A0A0A0A, TID = 0, OldProt;
HANDLE hTestThr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AtA, &a_arg, CREATE_SUSPENDED, &TID);


#endif
#endif