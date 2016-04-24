#pragma once
#define MAP_PAGE_SIZE 65536

#define PAGE_ROUND_DOWN(x) (((ULONG_PTR)(x)) & (~(MAP_PAGE_SIZE - 1)))
#define PAGE_ROUND_UP(x) ( (((ULONG_PTR)(x)) + MAP_PAGE_SIZE-1)  & (~(MAP_PAGE_SIZE-1)) )

#define CONFIG_MAP_NAME L"EhTraceConfigure"
#define SYMBOL_MAP_NAME L"EhTraceSymbols"

typedef struct _DiskSymbol
{
	unsigned long long Address;
	unsigned long long Length;
	//int NameLen;
	//int UDNameLen;
	wchar_t Name[1024];
	wchar_t UDName[1000];
} DiskSymbol, *PDiskSymbol;

typedef struct _NativeSymbol
{
	unsigned long long Address;
	unsigned long long Length;
	int NameLen;
	int UDNameLen;
	// mangled 
	const wchar_t* Name;
	// if un-mangled 
	const wchar_t* UDName;
} NativeSymbol, *PNativeSymbol;

typedef struct _ConfigContext
{
	unsigned long long SymCnt;
	PNativeSymbol SymTab;
	bool BasicSymbolsMode;
} ConfigContext, *PConfigContext;

void ConnectSymbols(int Cnt);
PConfigContext ConnectConfig();