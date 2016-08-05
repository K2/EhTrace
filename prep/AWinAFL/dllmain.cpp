// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
void options_init(int argc, char **argv);
void event_init(void);
void setup_pipe();
void setup_shmem();
void ExitThreadTable(ULONGLONG bit, bool Uninstall);

typedef void InitFighterFunc();

#define DEFENSIVE_MOVE 1
#define OFFENSIVE_MOVE 2
#define NO_FIGHTER 0
#define ROP_FIGHTER 1
#define ESCROW_FIGHTER 2
#define AFL_FLIGHTER 4

// Fighter ideas
// Stale Pointer on Free
// adapt ASAN/TSAN
// 
// mini heap sanity/pageheap on the fly
// 
typedef void FighterFunc(void* pCtx);

typedef struct _BlockFighters
{
	char *Module;
	char *Name;
	int Move;
	int Type;
	InitFighterFunc *InitFighter;
	FighterFunc *Fighter;
}
BlockFighters, *PBlockFighters;

void instrument_bb_coverage(PVOID px);
void instrument_edge_coverage(PVOID pCtx);
void InitFighters();
void ConfigureFighters(BlockFighters **Fighters, int cnt);
void post_fuzz_handler(PVOID px);
void pre_fuzz_handler(PVOID px);
bool AmIinThreadTable();
void EnterThreadTable(ULONGLONG bit, bool Install);
PExecutionBlock InitBlock(ULONG ID);
void ExitThreadTable(ULONG, bool);

extern ExecutionBlock *CtxTable;
BlockFighters bb_staticList[] = {
	{ NULL, "instrument_bb_coverage", DEFENSIVE_MOVE, ROP_FIGHTER, NULL, instrument_bb_coverage },
	{ NULL, "instrument_edge_coverage", DEFENSIVE_MOVE, ROP_FIGHTER, NULL, instrument_edge_coverage },
};

#define HOOK_FLAG_SUSPEND 0x10
#define HOOK_FLAG_RESUME 0x20

HookInfo GDIHooks[] = {

	{ "GdiplusStartup", FLAGS_PRE | HOOK_FLAG_SUSPEND, NULL, NULL, 2, 3, 0, NULL },
	{ "GdiplusShutdown", FLAGS_PRE | HOOK_FLAG_RESUME, NULL, NULL, 3, 4, 0, NULL },
	//{ "CryptDestroyKey", FLAGS_POST, NULL, NULL, 1, 1, 0, NULL},
	//{ "CryptDestroyHash", FLAGS_POST, NULL, NULL, 1, 1, 0, NULL },
	//{ "CryptReleaseContext", FLAGS_POST, NULL, NULL, 1, 1, 0, NULL },
};
int Initalize(PVECTORED_EXCEPTION_HANDLER Eh);

int GDIHookCount = sizeof(GDIHooks) / sizeof(GDIHooks[0]);
void InitHooks()
{
	HMODULE hADVAPI32DLL = GetModuleHandleA("gdiplus.dll");
	for (int i = 0; i < GDIHookCount; i++)
	{
		GDIHooks[i].RIP = (ULONG64)GetProcAddress(hADVAPI32DLL, GDIHooks[i].Name);
	}

}

CONTEXT SaveState;
bool HasState = false;

LONG WINAPI ATrace(PEXCEPTION_POINTERS ExceptionInfo)
{
	PExecutionBlock pCtx = NULL;
	ULONG64 dwThr = __readgsdword(0x48);
	int i;

	if (ExceptionInfo->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP || AmIinThreadTable())
		return EXCEPTION_CONTINUE_SEARCH;


	// no re-entrance while servicing exceptions
	EnterThreadTable(dwThr, false);

	// TODO: just put the whole context in the array to remove an indirect anyhow
	if (CtxTable != NULL && CtxTable[dwThr].TID != 0)
		pCtx = &CtxTable[dwThr];
	else
		pCtx = InitBlock(dwThr);

	pCtx->pExeption = ExceptionInfo;
	pCtx->TSC = __rdtsc();



	for (i = 0; i < 2; i++)
	{
		bb_staticList[i].Fighter(pCtx);
	}

	for (i = 0; i < 2; i++)
	{
		if (!HasState && (GDIHooks[i].Flags & HOOK_FLAG_SUSPEND) && GDIHooks[i].RIP == ExceptionInfo->ContextRecord->Rip)
		{
			HasState = true;
			memcpy(&SaveState, ExceptionInfo->ContextRecord, sizeof(SaveState));
		}
		if (HasState && (GDIHooks[i].Flags & HOOK_FLAG_RESUME) && GDIHooks[i].RIP == ExceptionInfo->ContextRecord->Rip)
		{
			memcpy(ExceptionInfo->ContextRecord, &SaveState, sizeof(SaveState));
		}
	}





	// Thanks Feryno
	// http://x86asm.net/articles/backdoor-support-for-control-transfer-breakpoint-features/
	// 
	ExceptionInfo->ContextRecord->EFlags |= 0x100; // single step
	ExceptionInfo->ContextRecord->Dr7 |= 0x300; // setup branch tracing 
	pCtx->BlockFrom = ExceptionInfo->ContextRecord->Rip;

	// exit lock
	ExitThreadTable(dwThr, false);

	return EXCEPTION_CONTINUE_EXECUTION;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		LPWSTR *szArglist;
		char **argv;
		int argc, i, len;

		InitHooks();

		szArglist = CommandLineToArgvW(GetCommandLineW(), &argc);
		argv = (char **)malloc(argc * sizeof(char*));
		for (i = 0; i < argc; i++)
		{
			len = wcslen(szArglist[i]);
			argv[i] = (char *)malloc(len);
			wcstombs(argv[i], szArglist[i], len + 1);
		}
		BlockFighters **dynList = (BlockFighters **)bb_staticList;


		ConfigureFighters(dynList, 2);
		printf("\n1\n");


		printf("\n2\n");
		options.nudge_kills = true;
		options.debug_mode = false;
		options.coverage_kind = COVERAGE_EDGE;
		options.target_modules = NULL;
		options.fuzz_module[0] = 0;
		options.fuzz_method[0] = 0;
		options.fuzz_offset = 0;
		options.fuzz_iterations = 1000;
		options.func_args = NULL;
		options.num_fuz_args = 0;
		snprintf(options.logdir, BUFFER_SIZE_ELEMENTS(options.logdir), ".");

		strcpy(options.pipe_name, "\\\\.\\pipe\\afl_pipe_default");
		strcpy(options.shm_name, "afl_shm_default");

		//options_init(argc, argv);


		if (!options.debug_mode) {
			setup_pipe();
			setup_shmem();
		}
		else {
			winafl_data.afl_area = (unsigned char *)malloc(MAP_SIZE);
		}
		printf("dllmain4\n");

		memset(winafl_data.cache, 0, sizeof(winafl_data.cache));
		memset(winafl_data.afl_area, 0, MAP_SIZE);

		winafl_data.previous_offset = 0;

		fuzz_target.iteration = 0;
		//event_init();

		printf("calling init\n");
		Initalize(ATrace);

		printf("init done\n");
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE; 
}

