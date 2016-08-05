#include "stdafx.h"

//  
// Good Overview/taxonomy of RoP protections in Defending against Return-Oriented Programming from Vasileios Pappas
// test a rop gadget, "4.2.1 Illegal Returns", one of several checks, but very good and fast in our context
// should include test for fibers and set/longjump?

//
// Interesting from https://msdn.microsoft.com/en-us/library/tawsa7cb.aspx
// 
// Clear rules on x64 make defensive options a bit more strict.
//
// These are the only legal forms for an epilog. It must consist of either an add RSP,constant or lea RSP,constant[FPReg],
// followed by a series of zero or more 8-byte register pops and a return or a jmp. (Only a subset of jmp statements are
// allowable in the epilog. These are exclusively of the class of jmps with ModRM memory references where ModRM mod field value 00.
// The use of jmps in the epilog with ModRM mod field value 01 or 10 is prohibited. See Table A-15 in the AMD x86-64 Architecture
// Programmer’s Manual Volume 3: General Purpose and System Instructions, for more info on the allowable ModRM references.). 
// No other code can appear. In particular, nothing can be scheduled within an epilog, including loading of a return value.
//
// Note that, when a frame pointer is not used, the epilog must use add RSP, constant to deallocate the fixed part of the stack.
// It may not use lea RSP, constant[RSP] instead.This restriction exists so the unwind code has fewer patterns to recognize when
// searching for epilogs.
//
// Following these rules allows the unwind code to determine that an epilog is currently being executed and to simulate execution
// of the remainder of the epilog to allow recreating the context of the calling function.
// 
// 
void RoPFighter(PVOID px)
{
	PExecutionBlock pCtx = (PExecutionBlock)px;

	// cache ? static std::set<unsigned int> s;
	// Clearly we need a stack pointer! Do we need this check?
	if (pCtx->pExeption->ContextRecord->Rsp == 0)
		return;

	// is the exception currently at a return ?
	unsigned long long *EipPtr = (unsigned long long *)pCtx->pExeption->ContextRecord->Rip;
	BYTE EipCheckOpCode = *((BYTE *)EipPtr);
	// if were not at any of these ret opcodes, then bail out since we have been raised at an instruction
	// that is not a ret #
	if (EipCheckOpCode != 0xc2 &&
		EipCheckOpCode != 0xc3 &&
		EipCheckOpCode != 0xca &&
		EipCheckOpCode != 0xcb &&
		EipCheckOpCode != 0xcf)
		return;

	// check for call instruction
	unsigned long long *FramePtr = (unsigned long long *)pCtx->pExeption->ContextRecord->Rsp;
	unsigned long long *RefFramePtr = (unsigned long long *)*FramePtr;
	BYTE *bp = (BYTE *)RefFramePtr;

	BYTE IsCallE8 = *((BYTE *)RefFramePtr - 5);
	BYTE IsCallE8_second = *((BYTE *)RefFramePtr - 3);
	BYTE IsCall9A = *((BYTE *)RefFramePtr - 5);
	BYTE IsCall9A_second = *((BYTE *)RefFramePtr - 7);

	//BYTE IsCallRegFF = *((BYTE *)RefFramePtr - 2);
	//BYTE IsCallFF = *((BYTE *)RefFramePtr - 6);

	bool FoundFFCode = false;
	// scan from RoPCheck
	for (int i = 2; i < 10; i++)
	{
		BYTE a = *((BYTE *)RefFramePtr - i);
		BYTE b = *((BYTE *)RefFramePtr - i + 1);

		if (i < 8) {
			if ((a == 0xff) && (b & 0x38) == 0x10)
			{
				FoundFFCode = true;
				break;
			}
		}
		if ((a == 0xff) && (b & 0x38) == 0x18)
		{
			FoundFFCode = true;
			break;
		}
	}

	if (!FoundFFCode && IsCallE8 != 0xe8 && IsCallE8_second !=  0xe8 && IsCall9A != 0x9a && IsCall9A_second != 0x9a) {
		printf("!!!!!!!!!!!!!!!!!!!!!! NO CALL FOUND !!!!!!!!!!!!!!!!!!!!!!\n");

		DWORD64 csRVA = (DWORD64)RefFramePtr;
		const uint8_t *csLocation = (const uint8_t *)csRVA;
		cs_disasm_iter(pCtx->handle, &csLocation, &pCtx->csLen, &csRVA, pCtx->insn);
		printf("%s\n", pCtx->insn->mnemonic);

		for (int i = 0; i < 8; i++)
			printf("0x%.02x ", *(bp + i));

		printf("\n");
	}
	//else
	//printf("++++++++++++++++++++++ Found CALL    ++++++++++++++++++++++\n");
}