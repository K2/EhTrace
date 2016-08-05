#include "stdafx.h"
//
// KeyFighter will register API handlers
// Long term use a generated configuration from clang decoding prototypes from public symbols
//
// pre hooks are easy since all the information is present at the time of the RIP invocation.
// post hooks we I suppose can log the RSP on entry to the function we care about 
// when RSP is adjusted at function exit we can extract our data, more than likely the stack value still valid
// 
// https://msdn.microsoft.com/en-us/library/ms235286.aspx
//
// Typically: First 4 parameters – RCX, RDX, R8, R9. 
//
//

//typedef ULONG64(__stdcall *FuncDef)(ULONG64 A1, ULONG64 A2, ULONG64 A3, ULONG64 A4, ULONG64 A5, ULONG64 A6, ULONG64 A7, ULONG64 A8, ULONG64 A9, ULONG64 A10, ULONG64 A11, ULONG64 A12, ULONG64 A13, ULONG64 A14, ULONG64 A15, ULONG64 A16);

#define FLAGS_POST	1
#define FLAGS_PRE	2
#define FLAGS_RESOLVE 4 // disassemble past 1 instruction to get where static linkers join
// blah these guys are not re-entrant safe since were keeping the RSP in here for tracking
// so don't hook re-entrant functions yet I guess ;)
//typedef struct _HookInfo { char *Name; ULONG64 Flags; ULONG64 RIP; ULONG64 RSP; DWORD ArgCnt; DWORD ArgRV; ULONG64 ArgLEN; BYTE* Result; }
// ARGLEN -1 MEANS READY/NO DATA
HookInfo HooksConfig[] = 
{
	{ "CryptGenRandom", FLAGS_POST, NULL, NULL, 2, 3, 0, NULL },
	//{ "CryptEncrypt", FLAGS_POST, NULL, NULL, 3, 4, 0, NULL },
	//{ "CryptDestroyKey", FLAGS_POST, NULL, NULL, 1, 1, 0, NULL},
	//{ "CryptDestroyHash", FLAGS_POST, NULL, NULL, 1, 1, 0, NULL },
	//{ "CryptReleaseContext", FLAGS_POST, NULL, NULL, 1, 1, 0, NULL },
};
int HookCount = sizeof(HooksConfig) / sizeof(HooksConfig[0]);

void InitKeyFighter()
{
	// Functions to monitor
	//  What do I want to know ?  
	// * Pre or Post hook 
	// ** Post hook bring in a intra-procedure analysis to establish function exits?
	// ** Derive the exits on the fly & cache results?
	// *** Mark SP on entry when it's being adjusted on return we 
	// ** Maybe happy path is all I care about :)
	// * 
	// * Pointer to memory to log (sane limits?)
	// * dwCount of data pointer
	// 
	// What do I want to hook ?
	// * CryptGenRandom 
	// * CryptEncrypt
	// * CryptProtectData
	// * CryptProtectMemory 
	// * CPEncrypt
	// * CryptCreateHash will need to export hash with CryptGetHashParam
	// * more bleh ? need make another code generator :)??

	csh handle;
	cs_opt_skipdata skipdata = { "db", };

	cs_open(CS_ARCH_X86, CS_MODE_64, &handle);

	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA_SETUP, (size_t)&skipdata);

	cs_insn *insn = cs_malloc(handle);
	size_t csLen = 16;
	DWORD64 JmpTarg = 0;

	HMODULE hADVAPI32DLL = GetModuleHandleA("Advapi32.dll");

	for (int i = 0; i < HookCount; i++)
	{
		HooksConfig[i].RIP = (ULONG64)GetProcAddress(hADVAPI32DLL, HooksConfig[i].Name);
#if _DEBUG
		if (HooksConfig[i].RIP == 0)
			printf("\n!!!FAILED GET PROC ADDRESS!!!\n");
#endif
		// not sure if we really care/want/need this resolve flag
		if (HooksConfig[i].Flags & FLAGS_RESOLVE)
		{
			DWORD64 csRVA = HooksConfig[i].RIP;
			const uint8_t *csLocation = (const uint8_t *)csRVA;

			// disassemble one instruction if it's an unconditional jump reset RIP to the target
			cs_disasm_iter(handle, &csLocation, &csLen, &csRVA, insn);

			cs_detail *detail = insn->detail;
			cs_x86 *x86 = &(insn->detail->x86);
			bool IsJmp = false;

			for (int g = 0; g < detail->groups_count; g++)
			{
				switch (detail->groups[g])
				{
				case CS_GRP_JUMP:
					IsJmp = true;
				}
			}
			if (IsJmp)
			{
				for (int optarg = 0; optarg < x86->op_count; optarg++)
				{
					cs_x86_op *op = &(x86->operands[optarg]);
					if ((int)op->type == X86_OP_MEM)
						JmpTarg = insn->address + insn->size + op->mem.disp;
					else if ((int)op->type == X86_OP_IMM)
						JmpTarg = op->imm;
					else
						; // JmpTarg = GetRegValue(op->reg);
				}

				HooksConfig[i].RIP = JmpTarg;
			}
		}
	}
}


ULONG64 inline GetArg(DWORD Cnt, PExecutionBlock pCtx)
{
	switch (Cnt)
	{
	case 1:
		return pCtx->pExeption->ContextRecord->Rcx;
	case 2:
		return pCtx->pExeption->ContextRecord->Rdx;
	case 3:
		return pCtx->pExeption->ContextRecord->R8;
	case 4:
		return pCtx->pExeption->ContextRecord->R9;
	}
	return 0;
}

void inline SetArg(DWORD Cnt, PExecutionBlock pCtx, DWORD64 Value)
{
	switch (Cnt)
	{
	case 1:
		pCtx->pExeption->ContextRecord->Rcx = Value;
	case 2:
		pCtx->pExeption->ContextRecord->Rdx = Value;
	case 3:
		pCtx->pExeption->ContextRecord->R8 = Value;
	case 4:
		pCtx->pExeption->ContextRecord->R9 = Value;
	}
}

void KeyFighter(void* px)
{
	ULONG64 ByteCount = 0;
	PExecutionBlock pCtx = (PExecutionBlock)px;

	ULONG64 RSP = pCtx->pExeption->ContextRecord->Rsp;
	ULONG64 RIP = pCtx->pExeption->ContextRecord->Rip;
	BYTE    *BytePtr = NULL;

	for (int i = 0; i < pCtx->HookCnt; i++)
	{
		bool CaptureInfo = false;

		// are we at a hookable Function?
		if (RIP == pCtx->Hooks[i].RIP)
		{
			if (pCtx->Hooks[i].Flags & FLAGS_POST)
			{
				// set RSP to the current value
				pCtx->Hooks[i].RSP = RSP;
			}
			else if (pCtx->Hooks[i].Flags & FLAGS_PRE)
				CaptureInfo = true;

			// capture the arg values that return info will be in
			pCtx->Hooks[i].ArgLEN = GetArg(pCtx->Hooks[i].ArgCnt, pCtx);
			pCtx->Hooks[i].Result = (BYTE*)GetArg(pCtx->Hooks[i].ArgRV, pCtx);
		}
		else if (pCtx->Hooks[i].RSP != 0)
		{
			// if RSP is set in the hook fn we look to see if it's time to log
			// pull data from our context 
			// this basically means were in a POST HOOK and the function is ready to return
			if (RSP > pCtx->Hooks[i].RSP)
			{
				// do log of data/egress
				CaptureInfo = true;

				// clear RSP so we do not keep logging junk ;)
				pCtx->Hooks[i].RSP = 0;
			}
		}
		// TODO: Send this out the network or something like a hypervisor protected memory section
		if (CaptureInfo)
		{
			ByteCount = pCtx->Hooks[i].ArgLEN;
			BytePtr = pCtx->Hooks[i].Result;
			if (ByteCount != 0 && BytePtr != NULL)
			{
				printf("\n+++++++++++++++++++++++++ CAPTURED FROM %s CALL, NOW LOG TO MY ESCROW +++++++++++++++++++++++++\n", pCtx->Hooks[i].Name);
				for (int e = 0; e < ByteCount; e++)
					printf("%.02x", *(BytePtr + e) & 0xff);
				printf("\n------------------------- BACK TO NORMAL ENJOY XTRA SET OF CRYPTO KEY -------------------------\n");
			}
		}
	}
}
