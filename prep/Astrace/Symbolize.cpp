#include "stdafx.h"
// setup main exe symbolization
//#include "Symbolize.h"
// Discover modules in use by target binary


// get symbols going for each of them
extern PConfigContext pConfig;

using namespace Dia2Sharp;
using namespace System;
using namespace System::Collections::Generic;

namespace AStrace {
	public ref class SymbolSetup abstract
	{
	public:
		static void SymSetup(PPROCESS_INFORMATION pi)
		{
			int cnt = 0;
			PMODULEENTRY32W pModules = NULL;
			List<MinSym^>^ ModSyms = nullptr;
			unsigned int Opts = 0x80000000;

			Globals::SymCtx = Sym::Initalize((DebugHelp::SymOptions) Opts);

			pModules = GetModStats(pi->dwProcessId, &cnt);

			for (int i = 0; i < cnt; i++)
			{
				if (wcsstr(pModules[i].szExePath, L"EhTrace"))
					continue;

				ModSyms = Globals::SymCtx->EnumSymsInFileWithVAOrder(%String(pModules[i].szExePath), (unsigned long long) pModules[i].modBaseAddr, pModules[i].modBaseSize);
				ModSyms->TrimExcess();
				Globals::SymCtx->ListAllSymbols->AddRange(ModSyms);
			}
			Globals::SymCtx->ListAllSymbols->TrimExcess();
			Globals::SymCtx->ListAllSymbols->Sort();
		}
	};
}