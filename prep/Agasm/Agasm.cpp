

#include "stdafx.h"
#include "Agasm.h"

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

I was going to avoid C++/CLI but it's so dammm useful!

*/


//#include "../asmjit-master/src/asmjit/asmjit.h"
//using namespace asmjit;
namespace Agasm
{
	//static String^ __clrcall GetASMStr(csh handle, cs_insn *insn, DissassemblyLine^ dissed);

	static int AdditonalSyms = 0;

#define STR_BUFF 512

	//bool GetBlock(unsigned __int64 RVA, PBYTE Location, csh handle, BasicBlock^% RV);

	// if we find the symbol we add that to the stream if we dont we simply write the adress
	bool __clrcall CheckSymbol(char *line, int64_t Address, int64_t Address2)
	{
		marshal_context context;
		const char* SymName = NULL;
		int i = 0;
		bool FoundSym = false;
		static bool OneTime = false;

		String^ mSymName = nullptr;

		if (Globals::CurrBasicInfoModule->ContainsKey(Address))
		{
			if (!Globals::CurrBasicInfoModule[Address]->Name->StartsWith("."))
			{
				mSymName = Regex::Replace(Globals::CurrBasicInfoModule[Address]->Name, "[^\\w+$]", "");
				SymName = context.marshal_as<const char*>(mSymName);
				strcat_s(line, STR_BUFF, SymName);
				FoundSym = true;
				AdditonalSyms++;
			}
		}

		if (!FoundSym && Address2 != 0)
			if (CheckSymbol(line, Address - ROUND_UP(Address2, 16), 0))
			{
				Debug::WriteLine("Second effort");
				AdditonalSyms++;
			}

		char numFmt[32];
		if (!FoundSym && Address2 == 0) {
			sprintf_s(numFmt, "0x%llx", Address);
			strcat_s(line, STR_BUFF, numFmt);
		}
		return FoundSym;
	}

	String^ GetSymName(int64_t Address)
	{
		String^ rv = String::Empty;
		char buff[STR_BUFF];
		buff[0] = '\0';

		if (CheckSymbol(buff, Address, 0) == true)
			rv = gcnew String(buff);

		return rv;
	}



	public ref class DissassemblyLine
	{
	public:
		DissassemblyLine(cs_insn *insn, char *line, FuncInfo^ fi)
		{
			if (line != NULL)
				NasmDisLine = gcnew String(line);

			this->Function = fi;
			this->Insn = insn;
			this->Detail = insn->detail;
			this->x86 = &insn->detail->x86;
			Address = insn->address;
			Length = insn->size;

			label = GetSymName(Address);

			PrefixLen = 0;
			for (int i = 0; i < 4; i++)
				if (x86->prefix[i] != 0)
					PrefixLen++;

			for (int i = 0; i < Detail->groups_count; i++)
				switch (Detail->groups[i]) {
				case CS_GRP_CALL:IsCall = true; break;
				case CS_GRP_INT: IsInt = true; break;
				case CS_GRP_JUMP: IsJmp = true; break;
				case CS_GRP_RET: IsRet = true; break;
				case CS_GRP_IRET: IsInt = true; break;
					//				case CS_GRP_PRIVILEGE: IsPriv = true; break;
				default: break;
				}

			if (x86->disp != 0)
				IsRelative = true;

			if (IsJmp || IsCall)
			{
				for (int i = 0; i < x86->op_count; i++)
				{
					cs_x86_op *op = &(x86->operands[i]);
					if ((int)op->type == X86_OP_MEM && (op->mem.segment == 41 || op->mem.base == 41 || op->mem.index == 41)) {
						IsRelative = true;
						JmpTargA = insn->address + insn->size + op->mem.disp;

						if (insn->id != X86_INS_JMP && insn->id != X86_INS_CALL)
							JmpTargB = insn->address + insn->size;
						else
							JmpTargB = 0;
					}
					else if ((int)op->type == X86_OP_IMM)
					{
						//JmpTargA = op->imm > 0 ? op->imm : (insn->address - (!op->imm));
						JmpTargA = op->imm;
						ImmDispA = JmpTargA - insn->address - insn->size;

						if (insn->id != X86_INS_JMP && insn->id != X86_INS_CALL)
							JmpTargB = insn->size;
						else
							JmpTargB = 0;
					}
				}
				if (IsCall)
				{
					Tuple<unsigned __int64, FuncInfo^>^ CallSource = Tuple::Create(Address, Function);
					Tuple<unsigned __int64, String^>^ CallTarg = Tuple::Create(JmpTargA, GetSymName(JmpTargA));

					if (!Globals::EdgeList->ContainsKey(CallSource))
						Globals::EdgeList->Add(CallSource, CallTarg);
					//else
					//if(Globals::EdgeList->ContainsKey(CallSource) && (Globals::EdgeList[CallSource] != CallTarg))
					//Globals::EdgeList->Add(CallSource, CallTarg);


				}
			}
		}
		unsigned __int64 ImmDispA;
		unsigned __int64 JmpTargA;
		unsigned __int64 JmpTargB;

		List<unsigned __int64> ReferencedBy;
		unsigned __int64 Address;
		unsigned short Length;
		unsigned short PrefixLen;
		bool IsEdge;	  // leaving the block
		bool IsRelative;  // synthesize these from the CapStone detail
		bool IsEntry;
		bool IsInt;
		bool IsJmp;
		bool IsCall;
		bool IsFar;
		bool IsRet;
		bool IsIret;
		bool IsPriv;
		cs_insn *Insn;
		cs_detail *Detail;
		cs_x86  *x86;
		String^	NasmDisLine;
		String^ label;
		FuncInfo^ Function;
		virtual property String^ Label { String^ get() sealed { return String::IsNullOrWhiteSpace(label) ? Address.ToString("X") : label; } }
		virtual String^ __clrcall ToString() override sealed
		{
			return Label + " " + Length + " " + NasmDisLine;
		}
	};




	String^ __clrcall GetASMStr(csh handle, cs_insn *insn, DissassemblyLine^ dissed)
	{
		char line[STR_BUFF * 2];
		char tmp[STR_BUFF];

		tmp[0] = '\0';

		cs_detail *detail = insn->detail;
		cs_x86 *x86 = &(insn->detail->x86);
		int i = 0, ImmOp = 0, RelativeOp = 0;
		bool IsCallJmp = dissed->IsCall | dissed->IsJmp;

		// if it's a call/jmp we check for a known symbol
		/*for (i = 0; i < detail->groups_count; i++)
		if (detail->groups[i] == CS_GRP_CALL || detail->groups[i] == CS_GRP_JUMP)
		IsCallJmp = true;*/

		if (IsCallJmp)
		{
			sprintf_s(line, "\t%s\t", insn->mnemonic);

			if (!CheckSymbol(line, dissed->JmpTargA, 0))

				for (int i = 0; i < detail->x86.op_count; i++)
				{
					cs_x86_op *op = &(x86->operands[i]);
					switch ((int)op->type)
					{
						/*case X86_OP_IMM:
						CheckSymbol(line, op->imm - ROUND_UP(insn->address + insn->size, 16), 0);
						break;*/
					case X86_OP_MEM:
						if (op->mem.segment == 41 || op->mem.base == 41 || op->mem.index == 41)
							;//CheckSymbol(line, insn->address + insn->size + op->mem.disp, 0);
						else
							strcat_s(line, insn->op_str);
						break;
					case X86_OP_REG:
						sprintf_s(tmp, "[%s]", cs_reg_name(handle, op->reg));
						strcat_s(line, insn->op_str);
						break;
					case X86_OP_FP:
					default:
						break;
					}
				}

			if (memcmp(insn->mnemonic, "db", 3) == 0)
				sprintf_s(tmp, "%s\n", insn->op_str);
			else if (dissed->IsCall)
				sprintf_s(tmp, "  ; %s \t %s \n", insn->mnemonic, insn->op_str);

			strcat_s(line, tmp);
		}
		else // not a jmp
		{
			for (int i = 0; i < detail->x86.op_count; i++)
			{
				cs_x86_op *op = &(x86->operands[i]);
				switch ((int)op->type) {
				case X86_OP_IMM:
					ImmOp = i;
					break;
				case X86_OP_MEM:
					if (op->mem.segment == 41 || op->mem.base == 41 || op->mem.index == 41)
						RelativeOp = i + 1;
					break;
				default:
					break;
				}
			}
			if (insn->id == X86_INS_NOP)
				sprintf_s(line, "\tnop\n");
			else if (insn->id == X86_INS_OUTSB || insn->id == X86_INS_OUTSD || insn->id == X86_INS_OUTSW
				|| insn->id == X86_INS_MOVSB || insn->id == X86_INS_MOVSW || insn->id == X86_INS_MOVSD || insn->id == X86_INS_MOVSQ
				|| insn->id == X86_INS_CMPSB || insn->id == X86_INS_CMPSW || insn->id == X86_INS_CMPSD || insn->id == X86_INS_CMPSQ
				|| insn->id == X86_INS_STOSB || insn->id == X86_INS_STOSW || insn->id == X86_INS_STOSD || insn->id == X86_INS_STOSQ
				|| insn->id == X86_INS_SCASD || insn->id == X86_INS_SCASB || insn->id == X86_INS_SCASQ || insn->id == X86_INS_SCASW)
			{
				sprintf_s(line, "\t%s\n", insn->mnemonic);
			}
			/*
			else if (insn->id == X86_INS_XRSTORS)
			{
			sprintf_s(line, "\txrstor\t%s\n", insn->op_str);
			}
			else if (insn->id == X86_INS_XSAVES || insn->id == X86_INS_XSAVEC)
			{
			sprintf_s(line, "\txsave\t%s\n", insn->op_str);
			}
			*/else if (insn->id == X86_INS_MOVABS)
			{
				sprintf_s(line, "\tmov\t");
				char *pc = NULL;
				if (strchr(insn->op_str, ','))
				{
					int code = 0;
					pc = strtok(insn->op_str, ",");
					while (pc != NULL)
					{
						if (code == ImmOp)
							sprintf_s(tmp, "[abs %s]", pc);
						else
							sprintf_s(tmp, "%s", pc);

						code++;
						if (code < detail->x86.op_count)
							strcat_s(tmp, ",");

						strcat_s(line, tmp);
						pc = strtok(NULL, ",");
					}
				}
				else {
					sprintf_s(tmp, "[abs %s]", insn->op_str);
					strcat_s(line, tmp);
				}

				strcat_s(line, "\n");
			}
			else
				sprintf_s(line, "\t%s\t%s\n", insn->mnemonic, insn->op_str);
		}
		return gcnew String(line);
	}


	public ref class BasicBlock
	{
	public:
		FuncInfo^ Function;
		BasicBlock^ TrueBlock;
		BasicBlock^ FalseBlock;
		List<unsigned __int64>^ AllRefTargets;
		List<unsigned __int64>^ TrueProcedureRefs;
		List<unsigned __int64>^ FalseProcedureRefs;

		SortedList<unsigned __int64, DissassemblyLine^>^ Lines;

		cs_insn *insn;
		size_t	csLength;
		bool	IsRetBlock;
		bool	IsStartBlock;
		csh		handle;
		PBYTE	Location;
		unsigned __int64 RVA;
		unsigned __int64 Address;

		BasicBlock(__int64 StartingAddr)
			:BasicBlock()
		{
			Length = 0;
			RVA = Address = StartingAddr;
			label = GetSymName(RVA);
		}
		BasicBlock()
		{
			Lines = gcnew SortedList<unsigned __int64, DissassemblyLine^>();
			AllRefTargets = gcnew List<unsigned __int64>();
			TrueProcedureRefs = gcnew List<unsigned __int64>();
			FalseProcedureRefs = gcnew List<unsigned __int64>();

		}
		BasicBlock(PBYTE Location, unsigned __int64 RVA, csh hnd, size_t csLen, cs_insn* insn)
			:BasicBlock(RVA)
		{
			this->insn = insn;
			csLength = csLen;
			handle = hnd;
			this->Location = Location;
		}

		// This is super same ending and starts later (higher)
		bool IsSub(BasicBlock ^isSub)
		{
			if (isSub->EndInsnAddr == EndInsnAddr && isSub->Address > Address && isSub->Address < Address + Length)
				return true;

			return false;
		}

		bool SplitAndLink(BasicBlock^ SubBlock)
		{
			if (IsSub(SubBlock) && EndInsnAddr != 0)
			{
				unsigned __int64 StartSub = SubBlock->Address;
				int LineCount = Lines->Count;
				Length = 0;

				SortedList<unsigned __int64, DissassemblyLine^>^ NewLines = gcnew SortedList<unsigned __int64, DissassemblyLine^>();

				for (int i = 0; i < LineCount; i++)
				{
					if (Lines->Keys[i] < StartSub) {
						NewLines->Add(Lines->Keys[i], Lines->Values[i]);
						Length += Lines->Values[i]->Length;
					}
				}

				Lines = NewLines;
				TrueProcedureRefs->Clear();
				TrueProcedureRefs->Add(SubBlock->Address);
				FalseProcedureRefs->Clear();

				// messing with thsese will blow the tree up
				//FalseBlock = nullptr;
				//TrueBlock = SubBlock;
				return true;
			}
			return false;
		}

		static BasicBlock^ BuildBlocks(PBYTE Location, unsigned __int64 RVA, csh hnd, size_t csLen, cs_insn* insn, BasicBlock^ Root)
		{
			BasicBlock^ Block = gcnew BasicBlock(RVA);
			Block->Function = Root->Function;

			const uint8_t *csLocation = (const uint8_t *)Location;
			unsigned __int64 csRVA = RVA;
			size_t cLen = csLen;
			bool Done = false;

			while (cs_disasm_iter(hnd, &csLocation, &cLen, &csRVA, insn) && !Done)
			{
				DissassemblyLine^ Line = gcnew DissassemblyLine(insn, NULL, Root->Function);
				Line->NasmDisLine = GetASMStr(hnd, insn, Line);

				Block->Lines->Add(Line->Address, Line);
				Block->Length += Line->Length;

				if (Line->IsRet || Line->IsIret)
					Done = Block->IsRetBlock = true;
				else if (Line->IsJmp)
				{
					if (!Block->TrueProcedureRefs->Contains(Line->JmpTargA))
						Block->TrueProcedureRefs->Add(Line->JmpTargA);

					if (!Root->AllRefTargets->Contains(Line->JmpTargA))
					{
						Root->AllRefTargets->Add(Line->JmpTargA);
						Block->TrueBlock = BuildBlocks((PBYTE)csLocation + Line->ImmDispA, Line->JmpTargA, hnd, cLen, insn, Root);
					}
					//// setup B PATH //// 
					if (Line->JmpTargB != 0)
					{
						unsigned __int64 bRVA = Line->Address + Line->JmpTargB;
						if (!Block->FalseProcedureRefs->Contains(bRVA))
							Block->FalseProcedureRefs->Add(bRVA);

						if (!Root->AllRefTargets->Contains(bRVA))
						{
							Root->AllRefTargets->Add(bRVA);
							Block->FalseBlock = BuildBlocks((PBYTE)csLocation, bRVA, hnd, cLen, insn, Root);
						}
					}

					// we did 1 or 2 branches, so they will now evaluate on their own
					// were done
					Done = true;
				}
			}
			return Block;
		}

		// return's count of edges
		void static GetBlocks(BasicBlock^ Root, List<BasicBlock^>^ Blocks, interior_ptr<int> EdgeCount)
		{
			if (!Blocks->Contains(Root))
				Blocks->Add(Root);

			if (Root->TrueBlock != nullptr && !Blocks->Contains(Root->TrueBlock))
			{
				Blocks->Add(Root->TrueBlock);
				GetBlocks(Root->TrueBlock, Blocks, EdgeCount);
				if (EdgeCount != nullptr)
					*EdgeCount = (*EdgeCount) + 1;
			}
			if (Root->FalseBlock != nullptr && !Blocks->Contains(Root->FalseBlock))
			{
				Blocks->Add(Root->FalseBlock);
				GetBlocks(Root->FalseBlock, Blocks, EdgeCount);
				if (EdgeCount != nullptr)
					*EdgeCount = (*EdgeCount) + 1;
			}
		}

		unsigned __int64 Length;

		virtual property unsigned long long EndInsnAddr { unsigned long long get() sealed
		{
			if (Lines->Count == 0) return 0;

			return Lines->Keys[Lines->Count - 1];
		}}

		String^ label;
		List<unsigned __int64>^ CallFrom = gcnew List<unsigned __int64>();
		//List<BasicBlock^>^ Blocks = gcnew List<BasicBlock^>();
		virtual property String^ Label { String^ get() sealed { return String::IsNullOrWhiteSpace(label) ? Address.ToString("X") : label; } }
	};

	public ref class DissassembledFunc
	{
	public:
		String^ CPrototype;  // int foo(void *bar);
		int ArgCount;

		unsigned __int64 Address;
		int Length;
		String^ label;
		BasicBlock^ Root;

		int _edgeCount;
		int _nodeCount;

		virtual property int EdgeCount { int get() sealed { return _edgeCount; }}
		virtual property int NodeCount { int get() sealed { return _nodeCount; }}

		virtual property String^ Label { String^ get() sealed { return String::IsNullOrWhiteSpace(label) ? Address.ToString("X") : label; } }
	};

	BasicBlock^ DoDoubleDiss(FILE *fo, PBYTE BaseVA, unsigned __int64 RVA, PBYTE Location, size_t Length, FuncInfo^ fi)
	{
		//JitRuntime runtime;
		//X86Assembler a(&runtime);
		FuncInfo^ TargetSym = nullptr;

		marshal_context context;
		const char* SymName = NULL;

		cs_opt_skipdata skipdata = { "db", };
		unsigned __int64 csRVA = RVA;
		const uint8_t *csLocation = (const uint8_t *)Location;
		size_t csLength = Length;
		csh handle;
		bool FoundRet = false;
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			return nullptr;

		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
		cs_option(handle, CS_OPT_SKIPDATA_SETUP, (size_t)&skipdata);

		cs_insn *insn = cs_malloc(handle);

		BasicBlock^ Root = gcnew BasicBlock(RVA);
		Root->Function = fi;

		BasicBlock^ start = BasicBlock::BuildBlocks(Location, csRVA, handle, Length, insn, Root);

		Root->FalseBlock = start->FalseBlock;
		Root->TrueBlock = start->TrueBlock;
		Root->IsRetBlock = start->IsRetBlock;
		Root->IsStartBlock = true;
		Root->TrueProcedureRefs = start->TrueProcedureRefs;
		Root->FalseProcedureRefs = start->FalseProcedureRefs;
		Root->Lines = start->Lines;
		if (String::IsNullOrWhiteSpace(Root->label))
			Root->label = start->Label;

		// serialize block tree into linear list
		List<BasicBlock^>^ Serialized = gcnew List<BasicBlock^>();
		BasicBlock::GetBlocks(Root, Serialized, nullptr);
		List<BasicBlock^>^ TrimFrom = gcnew List<BasicBlock^>(Serialized);

		// break blocks and link smaller sub-blocks to common sub-sections
		// scan each block through the list chopping off 
		for each (BasicBlock^ scan in Serialized)
		{
			for each(BasicBlock^ trim in TrimFrom)
			{
				if (scan == trim)
					continue;

				scan->SplitAndLink(trim);
			}
		}
		// 2 pass :(
		Serialized->Reverse();
		for each (BasicBlock^ scan in Serialized)
		{
			for each(BasicBlock^ trim in TrimFrom)
			{
				if (scan == trim)
					continue;

				scan->SplitAndLink(trim);
			}
		}

		cs_close(&handle);
		return Root;
	}

	void GenerateDissassembly(String^ Module, PBYTE ModMapp, ULONGLONG VABase, FILE* fo)
	{
		marshal_context context;
		int LastCodeLimit = 0;

		int loc = 0;
		array<KeyValuePair<unsigned int, FuncInfo^>>^ DupTable = gcnew array<KeyValuePair<unsigned int, FuncInfo^>>(Globals::FunctionTable[Module]->Count);
		// This is sort of irrelevant now I think // TODO: REMOVE
		for each(KeyValuePair<unsigned int, FuncInfo^> kvpData in Globals::FunctionTable[Module])
		{
			System::Text::StringBuilder^ Prototype = gcnew System::Text::StringBuilder(kvpData.Value->Name);

			// I don't really know the types yet from DIA, so everything is void*, their not really needed anyhow.
			DissassembledFunc^ Func = gcnew DissassembledFunc();
			kvpData.Value->DissData = Func;
			Func->Address = kvpData.Value->VirtualAddress;
			Func->ArgCount = kvpData.Value->ArgCount;
			Func->Length = kvpData.Value->Length;

			for (int i = 0; i < kvpData.Value->ArgCount; i++)
				Prototype->Append("void * " + kvpData.Value->ArgNames[i] + ((i + 1 == kvpData.Value->ArgCount) ? "" : ", "));

			Func->CPrototype = Prototype->ToString();

			// filter names down
			kvpData.Value->Name = Regex::Replace(kvpData.Value->Name, "[^\\w+$]", "");
			kvpData.Value->Name = kvpData.Value->Name + "_" + kvpData.Key.ToString("X");
			//DupTable[loc++] = KeyValuePair<unsigned int, FuncInfo^>(kvpData.Key, dynamic_cast<FuncInfo^>(kvpData.Value->Clone()));
			DupTable[loc++] = kvpData;
		}

		Globals::FunctionTableArray = DupTable;

		for (int i = 0; i < DupTable->Length; i++)
		{
			KeyValuePair<unsigned int, FuncInfo^> KVP = DupTable[i];
			//FuncInfo^ fi = dynamic_cast<FuncInfo^>(KVP.Value->Clone());
			FuncInfo^ fi = KVP.Value;

			if (LastCodeLimit != 0 && VABase < fi->VirtualAddress)
			{
				// do some data filler
				unsigned long long NeededPadding = fi->VirtualAddress - VABase;
				fprintf(fo, "\npadd_align_%llx: resb 0x%llxx\n\n", fi->VirtualAddress - NeededPadding, NeededPadding);
			}

			VABase = fi->VirtualAddress;
			if (fi->Length == 0 || String::IsNullOrWhiteSpace(fi->Name))
				continue;

			PBYTE funcPtr = GetBytesFromRVAMappedPE(fi->RVA, ModMapp);


			System::Text::StringBuilder^ InfoLine = gcnew System::Text::StringBuilder(";CurrAddr @ 0x");

			InfoLine->Append(fi->VirtualAddress.ToString("X"));
			InfoLine->Append("  " + fi->Name + "(");

			for each(String^ Arg in fi->ArgNames)
				InfoLine->Append(Arg + ", ");

			InfoLine->Append("); CodeLength: 0x" + fi->Length.ToString("X"));
			fi->InfoLine = InfoLine->ToString();
			const char* wInfoLine = context.marshal_as<const char*>(fi->InfoLine);
			fprintf(fo, "\n%s\n", wInfoLine);

			const char* wTrim = context.marshal_as<const char*>(fi->Name);
			fprintf(fo, "%s:\n", wTrim);

			DissassembledFunc^ dd = fi->DissData;
			dd->label = fi->Name + ":";

			BasicBlock^ root = DoDoubleDiss(fo, ModMapp, fi->VirtualAddress, funcPtr, ROUND_UP(fi->Length, 0x8), fi);

			dd->Root = root;

			// hey why not 3?
			// TODO: Fix the logic on these recursive functions through the blocks
			List<BasicBlock^>^ Serialized = gcnew List<BasicBlock^>();
			interior_ptr<int> pi = &dd->_edgeCount;
			BasicBlock::GetBlocks(root, Serialized, pi);
			dd->_nodeCount = Serialized->Count;

			VABase += root->Length;
		}
	}
#if EMIT_A_COMPLETE_ASM_FILE
	void ManageDissassembly(DissContext^ Dctx)
	{
		marshal_context context;

		for each(String^ Module in Dctx->FunctionTable->Keys)
		{
			int LastCodeLimit = 0;

			// need to fix for cases where PDB name != module name
			if (Path::GetFileNameWithoutExtension(Dctx->Module) == Module || "ntoskrnl.exe" == Dctx->Module)
				Dctx->ModMapp = MapFile(Dctx->Module);
			else
				Dctx->ModMapp = MapFile(Module);

			if (Dctx->ModMapp == NULL)
				continue;

			const char* dissName = context.marshal_as<const char*>(Module + ".asm");
			Dctx->fo = fopen(dissName, "w+");
			//Dctx->fo = stdout;
			if (Dctx->fo == NULL)
				printf("Can not open disassembly output file %s\n", dissName);
			else
			{
				fprintf(Dctx->fo, "[BITS 64]\n");
				fprintf(Dctx->fo, "[ORG 0x%llx]\n", Dctx->VABase);
				fprintf(Dctx->fo, "[DEFAULT REL]\n"); // use abs when cs gives us moveabs or rip addressing
				fprintf(Dctx->fo, "[SECTION .text]\n");
				// common intvar 4 // global
				// ABSOLUTE 0xADDRESS will adjust/aling to that location
				//fprintf(fo, "%%define RVA(x) (x - 0x%llx)\n", superlong);

				GenerateDissassembly(Module, Dctx->ModMapp, Dctx->VABase, Dctx->fo);

				fclose(Dctx->fo);
			}
		}
	}
#endif
}
