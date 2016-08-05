#pragma once
// organize externals here to help writing tests like as if we are a shared lib

extern "C" FARPROC AMain;

// Base this all in macro's or C++x11 or something to get some meta-ness to the fighters?
// Maybe they will get optimized together!
// What about using runtime code generation... RoP engine!
extern "C" void RoPFighter(PVOID pCtx);
extern "C" void KeyFighter(PVOID pCtx);
extern "C" void InitKeyFighter();
typedef struct _LDR_MODULE {



	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	HMODULE                 BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;

} LDR_MODULE, *PLDR_MODULE;

extern "C" PLDR_MODULE FirstModule();
