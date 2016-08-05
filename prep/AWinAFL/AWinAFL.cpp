/*
WinAFL - DynamoRIO client (instrumentation) code
------------------------------------------------

Written and maintained by Ivan Fratric <ifratric@google.com>

Copyright 2016 Google Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/


// EH WIN AFL PORT  (EhWinAFL)

#define _CRT_SECURE_NO_WARNINGS

#define MAP_SIZE 65536

#include "stdafx.h"



HookInfo HookxConfig[] = {
	{ "instrument_bb_coverage", FLAGS_POST, NULL, NULL, 2, 3, 0, NULL },
	{ "instrument_edge_coverage", FLAGS_PRE, NULL, NULL, 2, 3, 0, NULL },
	//{ "CryptGenRandom", FLAGS_POST | FLAGS_RESOLVE, NULL, NULL, 2, 3, 0, NULL },
	//{ "CryptEncrypt", FLAGS_POST, NULL, NULL, 3, 4, 0, NULL },
};



static void
event_nudge(void *drcontext, uint64 argument)
{
	int nudge_arg = (int)argument;
	int exit_arg = (int)(argument >> 32);
	/*
	if (nudge_arg == NUDGE_TERMINATE_PROCESS) {
	static int nudge_term_count;
	//handle multiple from both NtTerminateProcess and NtTerminateJobObject
	uint count = dr_atomic_add32_return_sum(&nudge_term_count, 1);
	if (count == 1) {
	dr_exit_process(exit_arg);
	}
	}*/
	//ASSERT(nudge_arg == NUDGE_TERMINATE_PROCESS, "unsupported nudge");
	//ASSERT(false, "should not reach"); /* should not reach */
}

static BOOL
event_soft_kill(process_id_t pid, int exit_code)
{
	/* we pass [exit_code, NUDGE_TERMINATE_PROCESS] to target process */
//	dr_config_status_t res;

	/*res = dr_nudge_client_ex(pid, client_id, NUDGE_TERMINATE_PROCESS | (uint64)exit_code << 32, 0);
	if (res == DR_SUCCESS) {
	return true;
	}
	*/
	/* else failed b/c target not under DR control or maybe some other
	* error: let syscall go through
	*/
	return false;
}

/****************************************************************************
* Event Callbacks
*/

static void dump_winafl_data()
{
	WriteFile(winafl_data.log, winafl_data.afl_area, MAP_SIZE, NULL, NULL);
}

static void
set_fuzz_file(char *filename) {
	strncpy(fuzz_target.testcase_filename, filename, MAXIMUM_PATH - 1);
	mbstowcs(fuzz_target.testcase_filename_w, filename, MAXIMUM_PATH - 1);
}

static BOOL
onexception(PExecutionBlock excpt) {
	DWORD num_written;
	DWORD exception_code = excpt->pExeption->ExceptionRecord->ExceptionCode;
	if ((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
		(exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
		(exception_code == EXCEPTION_PRIV_INSTRUCTION) ||
		(exception_code == EXCEPTION_STACK_OVERFLOW)) {
		if (options.debug_mode)
			//dr_fprintf(winafl_data.log, "crashed");
			if (!options.debug_mode)
				WriteFile(pipe, "C", 1, &num_written, NULL);
	}
	return true;
}

std::vector<PMODULEENTRY32W> modules;



void instrument_bb_coverage(PVOID px)
{
	const wchar_t *module_name = NULL;

	PExecutionBlock pCtx = (PExecutionBlock)px;

	app_pc Curr_PC = (app_pc)pCtx->pExeption->ExceptionRecord->ExceptionAddress;
	app_pc start = 0, end = 0;
	for (int i = 0; i < modules.size(); i++)
	{
		start = (app_pc)modules.at(i)->modBaseAddr;
		end = (app_pc)modules.at(i)->modBaseAddr + modules.at(i)->dwSize;
		if (Curr_PC > start && Curr_PC < end)
		{
			module_name = modules.at(i)->szModule;
		}
	}

	if (!module_name)
		return;

	uint offset = (uint)(Curr_PC - start);
	offset &= MAP_SIZE - 1;

	winafl_data.afl_area[offset]++;
}


// update the AFL logs for coverage
// 
wchar_t *target_mod = L"gdiplus.dll";

void instrument_edge_coverage(PVOID px)
{ 
	instr_t *new_instr;
	const wchar_t *module_name = NULL;
	uint offset;
	target_module_t *target_modules;
	BOOL should_instrument;

	PExecutionBlock pCtx = (PExecutionBlock)px;
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// look at all this module resolution =o
	app_pc Curr_PC = (app_pc)pCtx->pExeption->ExceptionRecord->ExceptionAddress;
	app_pc start = 0, end = 0;
	for (int i = 0; i < modules.size(); i++)
	{
		start = (app_pc)modules.at(i)->modBaseAddr;
		end = (app_pc)modules.at(i)->modBaseAddr + modules.at(i)->dwSize;
		if (Curr_PC > start && Curr_PC < end)
		{
			module_name = modules.at(i)->szModule;
		}
	}

	if (!module_name)
		return;

	should_instrument = false;
	target_modules = options.target_modules;
	while (target_modules) {
		if (_wcsicmp(module_name, target_mod) == 0) {
			should_instrument = true;
			break;
		}
		target_modules = (target_module_t *)target_modules->next;
	}
	if (!should_instrument) return;
	// check if I'm the dest of a call

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

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	offset = (uint)(Curr_PC - start);
	offset &= MAP_SIZE - 1;

	uint64 new_off = winafl_data.previous_offset ^ offset;
	uint64 *new_pos = (uint64 *)winafl_data.afl_area;

	offset = (offset >> 1)&(MAP_SIZE - 1);
	new_pos[offset]++;

	return;
}

void pre_fuzz_handler(PVOID px)
{
	char command = 0;
	int i;
	DWORD num_read;
	printf("in prep\n");
		
	PExecutionBlock pCtx = (PExecutionBlock)px;
	memcpy(&fuzz_target.CpuState, pCtx->pExeption->ContextRecord, sizeof(fuzz_target.CpuState));

	if (!options.debug_mode) {
		ReadFile(pipe, &command, 1, &num_read, NULL);

		if (command != 'F') {
			if (command == 'Q') {
				//dr_exit_process(0);
				;
			}
			else {
				DR_ASSERT_MSG(false, "unrecognized command received over pipe");
			}
		}
	}
	
	memset(winafl_data.afl_area, 0, MAP_SIZE);
	winafl_data.previous_offset = 0;
}

void post_fuzz_handler(PVOID px)
{
	DWORD num_written;
	static int numx = 0;
	PExecutionBlock pCtx = (PExecutionBlock)px;

	if (!options.debug_mode)
		WriteFile(pipe, "K", 1, &num_written, NULL);

	fuzz_target.iteration++;
	if (fuzz_target.iteration == options.fuzz_iterations) {
		TerminateProcess(GetCurrentProcess(), fuzz_target.iteration);
	}

	numx++;

	// cross fingers!
	printf("reverting %d", numx);
	memcpy(pCtx->pExeption->ContextRecord, &fuzz_target.CpuState, sizeof(fuzz_target.CpuState));
}

static void
event_module_unload(void *drcontext, const module_data_t *info)
{
	//	module_table_unload(module_table, info);
}


char *module_name;

static void
event_module_load(void *drcontext, const module_data_t *info, BOOL loaded)
{
	///const char *module_name = dr_module_preferred_name(info);
	app_pc to_wrap;

	if (options.debug_mode)
		printf("Module loaded, %s\n", module_name);

	if (options.fuzz_module[0]) {
		if (strcmp(module_name, options.fuzz_module) == 0) {
			if (options.fuzz_offset) {
				to_wrap = info->start + options.fuzz_offset;
			}
			else {
				
			}
			//drwrap_wrap(0, pre_fuzz_handler, post_fuzz_handler);

			// do init for this module


		}
	}
//	module_table_load(module_table, info);
}

static void
event_exit(void)
{
	if (options.debug_mode) {
		dump_winafl_data();
		//dr_close_file(winafl_data.log);
	}

	TerminateProcess(GetCurrentProcess(), -1);

}

void
event_init(void)
{
	char buf[MAXIMUM_PATH];

//	module_table = module_table_create();

	memset(winafl_data.cache, 0, sizeof(winafl_data.cache));
	memset(winafl_data.afl_area, 0, MAP_SIZE);

	winafl_data.previous_offset = 0;

	fuzz_target.iteration = 0;
}


void
setup_pipe() 
{
	//todo names should be per-clien in case of multithreading
	LPTSTR pipe_name = TEXT("\\\\.\\pipe\\afl_pipe_default");

	pipe = CreateFile(
		pipe_name,   // pipe name 
		GENERIC_READ |  // read and write access 
		GENERIC_WRITE,
		0,              // no sharing 
		NULL,           // default security attributes
		OPEN_EXISTING,  // opens existing pipe 
		0,              // default attributes 
		NULL);          // no template file 

	if (pipe == INVALID_HANDLE_VALUE) DR_ASSERT_MSG(false, "error connecting to pipe");
}
//
void
setup_shmem() {
   HANDLE map_file;

   map_file = OpenFileMappingA(
                   FILE_MAP_ALL_ACCESS,   // read/write access
                   FALSE,                 // do not inherit the name
                   options.shm_name);            // name of mapping object

   if (map_file == NULL) DR_ASSERT_MSG(false, "error accessing shared memory");

   winafl_data.afl_area = (unsigned char *) MapViewOfFile(map_file, // handle to map object
               FILE_MAP_ALL_ACCESS,  // read/write permission
               0,
               0,
               MAP_SIZE);

   if (winafl_data.afl_area == NULL) DR_ASSERT_MSG(false, "error accessing shared memory");
}


PMODULEENTRY32 GetModStats(DWORD pid, int *Cnt)
{
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	PMODULEENTRY32 rv = NULL;
	MODULEENTRY32 me32 = { 0 };
	me32.dwSize = sizeof(MODULEENTRY32);
	int currCnt = 0;

	if (hTool32 != INVALID_HANDLE_VALUE)
	{
		// calculate & Allocate for Cnt
		if (*Cnt == 0)
		{
			if (Module32First(hTool32, &me32)) {
				do {
					(*Cnt)++;
				} while (Module32Next(hTool32, &me32));
			}
		}

		rv = (PMODULEENTRY32)malloc(sizeof(MODULEENTRY32) * (*Cnt));
		if (Module32First(hTool32, &me32)) {
			do {
				if (*Cnt > currCnt) {
					rv[currCnt] = me32;
					currCnt++;
				}
			} while (Module32Next(hTool32, &me32));
		}

		CloseHandle(hTool32);
	}
	return rv;
}

void options_init(int argc, char **argv)
{

	printf("here");

	PMODULEENTRY32 pModStats = NULL;
	int cnt = 0;
	int i;
	const char *token;
	target_module_t *target_modules;
	/* default values */
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

	printf("here");

	for (i = 1/*skip client*/; i < argc; i++) {
		token = argv[i];
		if (strcmp(token, "-no_nudge_kills") == 0)
			options.nudge_kills = false;
		else if (strcmp(token, "-nudge_kills") == 0)
			options.nudge_kills = true;
		else if (strcmp(token, "-debug") == 0)
			options.debug_mode = true;
		else if (strcmp(token, "-logdir") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing logdir path");
			strncpy(options.logdir, argv[++i], BUFFER_SIZE_ELEMENTS(options.logdir));
		}
		else if (strcmp(token, "-fuzzer_id") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing fuzzer id");
			strcpy(options.pipe_name, "\\\\.\\pipe\\afl_pipe_");
			strcpy(options.shm_name, "afl_shm_");
			strcat(options.pipe_name, argv[i + 1]);
			strcat(options.shm_name, argv[i + 1]);
			i++;
		}
		else if (strcmp(token, "-covtype") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing coverage type");
			token = argv[++i];
			if (strcmp(token, "bb") == 0) options.coverage_kind = COVERAGE_BB;
			else if (strcmp(token, "edge") == 0) options.coverage_kind = COVERAGE_EDGE;
			else USAGE_CHECK(false, "invalid coverage type");
		}
		else if (strcmp(token, "-coverage_module") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing module");
			target_modules = options.target_modules;
			options.target_modules = (target_module_t *)malloc(sizeof(target_module_t));
			options.target_modules->next = target_modules;
			strncpy(options.target_modules->module_name, argv[++i], BUFFER_SIZE_ELEMENTS(options.target_modules->module_name));
		}
		else if (strcmp(token, "-target_module") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing module");
			strncpy(options.fuzz_module, argv[++i], BUFFER_SIZE_ELEMENTS(options.fuzz_module));
		}
		else if (strcmp(token, "-target_method") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing method");
			strncpy(options.fuzz_method, argv[++i], BUFFER_SIZE_ELEMENTS(options.fuzz_method));
		}
		else if (strcmp(token, "-fuzz_iterations") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing number of iterations");
			options.fuzz_iterations = atoi(argv[++i]);
		}
		else if (strcmp(token, "-nargs") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing number of arguments");
			options.num_fuz_args = atoi(argv[++i]);
		}
		else if (strcmp(token, "-target_offset") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing offset");
			options.fuzz_offset = strtoul(argv[++i], NULL, 0);
		}
		else if (strcmp(token, "-verbose") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing -verbose number");
			token = argv[++i];
			if (sscanf(token, "%u", &verbose) != 1) {
				USAGE_CHECK(false, "invalid -verbose number");
			}
		}
		else {
			//    NOTIFY(0, "UNRECOGNIZED OPTION: \"%s\"\n", token);
			USAGE_CHECK(false, "invalid option");
		}
		options.num_fuz_args = 2;
		options.fuzz_offset = 0x1270;

	}

	if (options.fuzz_module[0] && (options.fuzz_offset == 0) && (options.fuzz_method[0] == 0)) {
		USAGE_CHECK(false, "If fuzz_module is specified, then either fuzz_method or fuzz_offset must be as well");
	}

	if (options.num_fuz_args) {
		options.func_args = (void **)malloc(options.num_fuz_args * sizeof(void *));
	}

	// enumerate modules and configure module notification
	// get cnt
	/*
	GetModStats(GetCurrentProcessId(), &cnt);
	if (cnt != 0)
		pModStats = GetModStats(GetCurrentProcessId(), &cnt);

	if (cnt == 0 || pModStats == NULL)
		return;
		*/

}
