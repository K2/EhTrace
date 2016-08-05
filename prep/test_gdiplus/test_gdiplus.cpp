// test_gdiplus.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


using namespace Gdiplus;
ULONG64 Counter = 0;
static HANDLE pipe;

wchar_t* charToWChar(const char* text)
{
	size_t size = strlen(text) + 1;
	wchar_t* wa = new wchar_t[size];
	mbstowcs(wa, text, size);
	return wa;
}

void setup_pipe()
{
	//todo names should be per-client in case of multithreading
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

	if (pipe == INVALID_HANDLE_VALUE) printf("error connecting to pipe\n");
}

void EnterThreadTable(ULONGLONG bit, bool Install);
void ExitThreadTable(ULONGLONG bit, bool Uninstall);
bool InitThreadTable(ULONGLONG Cnt);

ULONG64 GDIPLUS_START=0, GDIPLUS_END=0;
extern PExecutionBlock CtxTable;

// VEH should always allow for us not to worry about this guy?
LONG WINAPI xBossLevel(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	DWORD OldPerm;
	printf("boss");
	ULONG64 dwThr = __readgsdword(0x48);
	PExecutionBlock pCtx = NULL;

	if (CtxTable != NULL && CtxTable[dwThr].TID != 0)
		pCtx = &CtxTable[dwThr];

	ULONG64 Addy = (ULONG64) ExceptionInfo->ExceptionRecord->ExceptionAddress & ~0x4095;

	if (Addy == (ULONG64) pCtx->DisabledUntil)
		VirtualProtect(ExceptionInfo->ExceptionRecord->ExceptionAddress, 4096, PAGE_EXECUTE_READ, &OldPerm);

	// in range turn on monitoring
	if ((ULONG64) ExceptionInfo->ExceptionRecord->ExceptionAddress > GDIPLUS_START &&
		(ULONG64) ExceptionInfo->ExceptionRecord->ExceptionAddress < GDIPLUS_END)
	{
		printf("in gdiplus keep permission running?");
		// only re-enable if rip is in the gdiplus range
		ExceptionInfo->ContextRecord->EFlags |= 0x100; // single step
		ExceptionInfo->ContextRecord->Dr7 |= 0x300; // setup branch tracing 
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}

void printfcomma(ULONG64 n) {
	if (n < 1000) {
		printf("%d", n);
		return;
	}
	printfcomma(n / 1000);
	printf(",%03d", n % 1000);
}
static ULONG64 get_cur_time_us(void) {

	ULONG64 ret;
	FILETIME filetime;
	GetSystemTimeAsFileTime(&filetime);

	ret = ((filetime.dwHighDateTime) << 32) + filetime.dwLowDateTime;

	return ret / 10;
}



int main(int argc, char** argv)
{
	SetUnhandledExceptionFilter(&xBossLevel);

	setlocale(LC_NUMERIC, "");

	GDIPLUS_START = (ULONG64) GetModuleHandle(TEXT("gdiplus.dll"));
	GDIPLUS_END = GDIPLUS_START + 0x147600;

	DWORD num_written;
	char *imagename = "test.bmp";
	if (argc != 2) {
		printf("Usage: %s <image file>\n", argv[0]);
	}
	else
		imagename = argv[1];

	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;

	printf("Startup testing [%s]\n", imagename);
	int cnt = 0;
	setup_pipe();

	DWORD64 time = __rdtsc(), time2 = __rdtsc();
	ULONG64 utime = get_cur_time_us(), utime2 = get_cur_time_us();
	wchar_t *wname = charToWChar(imagename);

	DWORD tid = GetCurrentThreadId();

	//InitThreadTable(1000 * 100);
	CONTEXT Ctx = { 0 };
	Ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	AMain();

	while (true)
	{
		Image *image = NULL, *thumbnail = NULL;

		time = __rdtsc();
		utime = get_cur_time_us();

		GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

		image = new Image(wname);
		if (image && (Ok == image->GetLastStatus())) {
			//printf("Image loaded\n");
			/*thumbnail = image->GetThumbnailImage(100, 100, NULL, NULL);
			if(thumbnail && (Ok == thumbnail->GetLastStatus())) {
			//printf("Thumbnail created\n");
			}*/
		}

		if (image) delete image;
		if (thumbnail) delete thumbnail;

		GdiplusShutdown(gdiplusToken);
		time2 = __rdtsc();
		utime2 = get_cur_time_us();

		Counter++;

		if ((Counter % 100) == 0)
		{
			
			printf("iterations: %d \t Cycles : ", Counter);
			printfcomma(time2 - time);
			printf("\t usecs: ");
			printfcomma(utime2 - utime);

			utime = get_cur_time_us();
			printf("\n");
		}
		//WriteFile(pipe, "K", 1, &num_written, NULL);
	}

	return 0;
}

