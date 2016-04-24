#include "stdafx.h"
#include "../EhTrace/Config.h"


// whoever loads our context should also pre-parse any configuration file into a structured format
PConfigContext ConfigMap = NULL;
PNativeSymbol SymTab = NULL;

HANDLE hConfigMap = INVALID_HANDLE_VALUE;
HANDLE hSymMap = INVALID_HANDLE_VALUE;

void ConnectSymbols(int Cnt)
{
	DWORD size = Cnt * sizeof(NativeSymbol);

	DWORD align_size = PAGE_ROUND_UP(size);

	hSymMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0x0000000, align_size, SYMBOL_MAP_NAME);
	SymTab = (PNativeSymbol)MapViewOfFile(hSymMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (!SymTab)
	{
		wprintf(L"unable to map symbol data.");
		return;
	}
	wprintf(L"symbol buffer is @ %p\n", SymTab);
	
	ConfigMap->SymTab = SymTab;
	ConfigMap->SymCnt = Cnt;
}

PConfigContext ConnectConfig()
{
	ULONG64 PaddedSize = PAGE_ROUND_UP(sizeof(ConfigContext));
	ULONG64 ConfigSize = PaddedSize;

	hConfigMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, PaddedSize >> 32, PaddedSize, CONFIG_MAP_NAME);
	ConfigMap = (PConfigContext) MapViewOfFile(hConfigMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (!ConfigMap)
	{
		wprintf(L"unable to map shared configuration data, default operations.");
		return NULL;
	}
	wprintf(L"ConfigMap buffer is @ %p\n", ConfigMap);
	
	return ConfigMap;
}
void ConfigureContext()
{
	if (!ConnectConfig())
		return;

	// scan configuration for options:
	//
	// BasicSymbolsMode - Log only when RIP is @ a known symbol
	// 



}