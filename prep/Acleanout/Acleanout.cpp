// Acleanout.cpp : Defines the entry point for the console application.

#include "stdafx.h"	


// just loop and dump info 
void LogDump()
{
	Step_Event* se;
	while (true)
	{
		se = LogPopIP();
		if (se != NULL && se->RIP != 0)
		{
			wprintf(L"tid [%d] flags[%x] rip[%llx]\n", se->u.TID, se->u.eFlags, se->RIP);
			se->RIP = 0;
			se->u.Synth = 0;
			se = NULL;
		}
		Sleep(0);
	}
}

// log to a file
void LogToFile(wchar_t* OutFile)
{
	HANDLE hOutFile = CreateFile(OutFile, GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	Step_Event* se;
	LONG64 LogCnt = 1;
	DWORD wrote = 0;

	while (hOutFile != INVALID_HANDLE_VALUE)
	{
		// We should try to queue up 4096/sizeof(step_event) and do writes based on 4k
		// then flush out if we get any of the CtrlHandler events
		// double check to unblock LogPopIP
		se = LogPopIP();
		if (se != NULL && se->RIP != 0)
		{
			if (!WriteFile(hOutFile, se, sizeof(Step_Event) * LogCnt, &wrote, NULL))
			{
				wprintf(L"Error writing output file %s", OutFile);
				return;
			}
			memset(se, 0, sizeof(Step_Event) * LogCnt);
			se = NULL;
		}
		else
			Sleep(0);
	}
}

static bool DoExit = false;

BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
		case CTRL_C_EVENT:
		{
			if (DoExit)
				return false;

			printf("Flushing/closing Control-C again to exit\n\n");
			DoExit = true;
			return(TRUE);
		}
	}
	return false;
}

int wmain(int argc, wchar_t* argv[])
{
	wchar_t* OutputPath = NULL;

	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);
	ConnectLogBuffer(STRACE_LOG_BUFFER_SIZE);
	
	if (argc < 2)
		LogDump();
	else if(argc == 2)
	{
		OutputPath = _wcsdup(argv[1]);
		wprintf(L"output file is %s\n", OutputPath);
		LogToFile(OutputPath);
	}
	else
	{
		wprintf(L"no arguments will dump logs to screen.\n");
		wprintf(L"supply a file path to dump to a file.\n");
		return -1;
	}

	return 0;
}

