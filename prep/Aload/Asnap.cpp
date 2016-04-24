#include "stdafx.h"

#ifndef IN_ALOAD 
#define IN_ALOAD  false
#endif


PMODULEENTRY32W GetModStats(DWORD pid, int *Cnt)
{
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	PMODULEENTRY32W rv = NULL;
	MODULEENTRY32W me32 = { 0 };
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

		rv = (PMODULEENTRY32W)malloc(sizeof(MODULEENTRY32W) * (*Cnt));
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


int GetModStatsToFile(wchar_t *modStats, DWORD pid)
{
	PMODULEENTRY32W pModStats = NULL;
	int cnt = 0;

	if (modStats != NULL)
	{

		// get cnt
		GetModStats(pid, &cnt);
		if (cnt != 0)
			pModStats = GetModStats(pid, &cnt);
		
		if(cnt == 0 || pModStats == NULL)
			return -2;

		if(IN_ALOAD) wprintf(L"dumping module stats to file %s, record size %llx\n", modStats, sizeof(MODULEENTRY32W));
		
		HANDLE hStatsFile = CreateFile(modStats, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (hStatsFile == INVALID_HANDLE_VALUE)
		{
			if(IN_ALOAD) wprintf(L"unable to make module stats file %s\n", modStats);
			return -3;
		}

		for (int i = 0; i < cnt; i++)
		{
			if (IN_ALOAD)
				wprintf(L"BASE: [0x%llx] Length: [0x%x] Path [%s]\n", pModStats[i].modBaseAddr, pModStats[i].modBaseSize, pModStats[i].szExePath);
			if (!WriteFile(hStatsFile, &pModStats[i], sizeof(MODULEENTRY32W), NULL, NULL))
				if (IN_ALOAD)
					wprintf(L"Unable to write data error %d\n", GetLastError());
		}

		CloseHandle(hStatsFile);
	}
	return 0;
}