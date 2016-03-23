
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


#include "stdafx.h"

extern bool MinOutput;

namespace Agasm
{
	/*Convert Virtual Address to File Offset */
	ULONGLONG Rva2Offset(ULONGLONG rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
	{
		size_t i = 0;
		PIMAGE_SECTION_HEADER pSeh;
		if (rva == 0)
		{
			return (rva);
		}
		pSeh = psh;
		for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
		{
			if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
				pSeh->Misc.VirtualSize)
			{
				break;
			}
			pSeh++;
		}
		return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
	}

	PBYTE GetBytesFromRVAMappedPE(ULONGLONG RVA, BYTE *PE)
	{
		PIMAGE_DOS_HEADER pdosHeader;
		PIMAGE_NT_HEADERS pntHeader;
		PIMAGE_SECTION_HEADER pSection;

		pdosHeader = (PIMAGE_DOS_HEADER)PE;

		pntHeader = (PIMAGE_NT_HEADERS)((char *)pdosHeader + pdosHeader->e_lfanew);
		if (pntHeader->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		pSection = IMAGE_FIRST_SECTION(pntHeader);

		return PE + Rva2Offset(RVA, pSection, pntHeader);
	}

	PBYTE MapFile(String ^File)
	{
		HANDLE hFile, hFileMapping;
		hFile = hFileMapping = INVALID_HANDLE_VALUE;

		if (String::IsNullOrWhiteSpace(File)) return NULL;
		marshal_context^ x = gcnew marshal_context();
		const wchar_t *nFile = x->marshal_as<const wchar_t*>(File);

		hFile = CreateFileW((wchar_t *)nFile, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
		if (hFile == INVALID_HANDLE_VALUE) return NULL;

		DWORD sizeLow = GetFileSize(hFile, NULL);

		hFileMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hFileMapping == INVALID_HANDLE_VALUE) return NULL;

		return (PBYTE)MapViewOfFile(hFileMapping, SECTION_MAP_READ, 0, 0, 0);
	}


#if NOT_USING_YET

	static array<CLR_PE_SECTIONS^>^ GetPESections(Stream^ File)
	{
		array<Byte>^ buff = gcnew array<Byte>((int)File->Length);

		int i = File->Read(buff, 0, buff->Length);
		if (i != buff->Length)
			Console::WriteLine("Short read from input stream");

		pin_ptr<Byte> pbuff = &buff[0];

		return IOAHook2::GetPESections(pbuff, (int)File->Length, false, true, 0);
	}

	array<CLR_PE_SECTIONS^>^ GetPESections(String^ File, bool UseVA, bool DoImports)
	{
		array<CLR_PE_SECTIONS^>^ rv = nullptr;
		BYTE *bp = NULL;
		HANDLE hFile, hFileMapping;

		hFile = hFileMapping = INVALID_HANDLE_VALUE;

		if (String::IsNullOrWhiteSpace(File)) return rv;
		marshal_context^ x = gcnew marshal_context();
		const wchar_t *nFile = x->marshal_as<const wchar_t*>(File);

		hFile = CreateFileW((wchar_t *)nFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0, OPEN_EXISTING, 0, 0);
		if (hFile == INVALID_HANDLE_VALUE) return rv;

		DWORD sizeLow = GetFileSize(hFile, NULL);

		__try {

			//	HMODULE base = LoadLibraryExW(nFile, 0, DONT_RESOLVE_DLL_REFERENCES);
			//	if (base)
			//		rv = GetPESections((PBYTE)base, sizeLow, UseVA, DoImports, 0);
			//	else
			//	{
			hFileMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
			if (hFileMapping == INVALID_HANDLE_VALUE) return rv;

			bp = (BYTE *)MapViewOfFile(hFileMapping, SECTION_MAP_READ, 0, 0, 0);
			if (bp == NULL) return rv;

			rv = GetPESections(bp, sizeLow, UseVA, DoImports, 0);

			rv[0]->FileName = File;
			//	}
		}
		__finally {
			if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
			if (hFileMapping != INVALID_HANDLE_VALUE) CloseHandle(hFileMapping);
			if (bp != NULL) UnmapViewOfFile(bp);
		}

		return rv;
	}

	// assumption is that the IAT is at the beginning of a section
	array<CLR_PE_SECTIONS^>^ GetPESections(BYTE *bp, int Max, bool UseVA, bool DoImports, ULONGLONG OrigImageBase)
	{
		PIMAGE_DOS_HEADER pdosHeader;
		PIMAGE_NT_HEADERS pntHeader;
		PIMAGE_OPTIONAL_HEADER32 pNTHeader32;
		PIMAGE_OPTIONAL_HEADER64 pNTHeader64;
		PIMAGE_SECTION_HEADER pSection, aSection;
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
		PCODEVIEW_HEADER pcv;

		ULONGLONG iDataLoc, iDataSize = 0, ImageBase, clrAddr, SectionAlignment, FileAlignment;
		ULONG32 iDebugLoc = 0, iDebugSize, cvRawPtr = 0, importSize, importLoc;
		ULONG32 TimeDate, cfgOff = 0;
		DWORD CheckSum, HeaderSize, PatchLoc = 0, SizeOfImage = 0;

		unsigned short int cnt;

		// BUGBUG: Do we want to repair headers?
		//int fixoff;
		array<CLR_PE_SECTIONS^>^ rv = nullptr;
		CLR_PE_SECTIONS^ Header;
		//array<CLR_RELOC_INFO^>^ relocs = nullptr;

		bool is64app = false, isCLR = false;

		pdosHeader = (PIMAGE_DOS_HEADER)bp;

		// check for overflows and bad inputs here 
		if (pdosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) < sizeof(IMAGE_NT_HEADERS) || sizeof(IMAGE_NT_HEADERS) + pdosHeader->e_lfanew  > Max)
			return rv;

		if (pdosHeader == NULL || pdosHeader->e_magic != IMAGE_DOS_SIGNATURE || pdosHeader->e_lfanew >= Max)
			return rv;

		pntHeader = (PIMAGE_NT_HEADERS)((char *)pdosHeader + pdosHeader->e_lfanew);
		if (pntHeader->Signature != IMAGE_NT_SIGNATURE)
			return rv;

		cnt = pntHeader->FileHeader.NumberOfSections;
		if (cnt <= 0)
			return rv;
		// The windows loader limit's the count of sections to 96
		if (cnt > 96)
			cnt = 96;

		TimeDate = pntHeader->FileHeader.TimeDateStamp;

		if (TimeDate == 0x0)
			Console::WriteLine("NO TIME");

		if (pntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			is64app = true;

		if (is64app)
		{
			pNTHeader64 = (PIMAGE_OPTIONAL_HEADER64)&pntHeader->OptionalHeader;

			if (pNTHeader64->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
				cfgOff = pdosHeader->e_lfanew + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, DllCharacteristics);

			if (OrigImageBase != 0)
				pNTHeader64->ImageBase = OrigImageBase;

			ImageBase = pNTHeader64->ImageBase;
			HeaderSize = pNTHeader64->SizeOfHeaders;
			CheckSum = pNTHeader64->CheckSum;
			SectionAlignment = pNTHeader64->SectionAlignment;
			FileAlignment = pNTHeader64->FileAlignment;
			SizeOfImage = pNTHeader64->SizeOfImage;

			importLoc = pNTHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			importSize = pNTHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

			iDataLoc = pNTHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
			iDataSize = pNTHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

			iDebugLoc = pNTHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
			iDebugSize = pNTHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

			clrAddr = pNTHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
			if (clrAddr != 0)
				isCLR = true;
		}
		else
		{
			pNTHeader32 = (PIMAGE_OPTIONAL_HEADER32)&pntHeader->OptionalHeader;

			if (pNTHeader32->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
				cfgOff = pdosHeader->e_lfanew + FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, DllCharacteristics);

			if (OrigImageBase != 0)
				pNTHeader32->ImageBase = (ULONG)OrigImageBase;

			ImageBase = pNTHeader32->ImageBase;
			HeaderSize = pNTHeader32->SizeOfHeaders;
			CheckSum = pNTHeader32->CheckSum;
			SectionAlignment = pNTHeader32->SectionAlignment;
			FileAlignment = pNTHeader32->FileAlignment;
			SizeOfImage = pNTHeader32->SizeOfImage;

			importLoc = pNTHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			importSize = pNTHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

			iDataLoc = pNTHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
			iDataSize = pNTHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

			iDebugLoc = pNTHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
			iDebugSize = pNTHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

			clrAddr = pNTHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
			if (clrAddr != 0)
				isCLR = true;
		}

		if (pntHeader->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
			is64app = false;

		// if we are a CLR binary, we need to re-adjust iDataSize if it's been cleared
		if (isCLR && iDataSize == 0)
		{
			iDataSize = clrAddr - pntHeader->OptionalHeader.BaseOfCode;
			iDataLoc = clrAddr - iDataSize;
		}

		pSection = IMAGE_FIRST_SECTION(pntHeader);

		// add a section for the header itself
		// the header is inserted after to ensure we have properly assigned the length of the header
		// which is derived from detecting the start of the first (by file offset) section
		cnt++;

		rv = gcnew array<CLR_PE_SECTIONS^>(cnt);

		// populate from position 1, reserving 0 for the header
		for (int l = 1; l < cnt; l++)
		{
			// subtract one from 1(the source array is 0 indexed)
			aSection = &pSection[l - 1];

			rv[l] = gcnew CLR_PE_SECTIONS;

			// TimeDateStamp is used for relocation resolution
			rv[l]->TimeDateStamp = TimeDate;

			// this may also help locate reloc data
			rv[l]->CheckSum = CheckSum;

			if (UseVA)
			{
				rv[l]->StartOff = aSection->VirtualAddress;
				// this will handle sections that have more memory load then disk space!
				rv[l]->Length = (aSection->Misc.VirtualSize > aSection->SizeOfRawData) ? aSection->Misc.VirtualSize : aSection->SizeOfRawData;
			}
			else
			{
				rv[l]->StartOff = aSection->PointerToRawData;
				rv[l]->Length = aSection->SizeOfRawData;
			}

			// find out what distance we have to null fill
			//rv[l]->PostPadAlign = (rv[l]->Length % SectionAlignment) != 0 ? SectionAlignment - (rv[l]->Length % SectionAlignment) : 0;
			rv[l]->PostPadAlign = ROUND_UP(rv[l]->Length, 4096) - rv[l]->Length;

			// trim this section as it's VA is the same as the IAT
			if (iDataLoc == aSection->VirtualAddress && !isCLR)
			{
				rv[l]->StartOff += iDataSize;
				rv[l]->Length -= (unsigned int)iDataSize;
				rv[l]->PrePadAlign = (unsigned int)iDataSize;
			}
			rv[l]->IsCLRApp = isCLR;
			rv[l]->Is64bit = is64app;
			rv[l]->IsCode = aSection->Characteristics & IMAGE_SCN_CNT_CODE;
			rv[l]->IsExec = aSection->Characteristics & IMAGE_SCN_MEM_EXECUTE;
			rv[l]->IsWriteable = aSection->Characteristics & IMAGE_SCN_MEM_WRITE;

			rv[l]->ImageBase = ImageBase;
			rv[l]->VirtualSize = aSection->Misc.VirtualSize;
			rv[l]->SectionName = (gcnew String((char *)aSection->Name, 0, 8))->Trim('\0');

			// CLR binaries have a patch instruction that we can account for
			if (isCLR && rv[l]->SectionName != nullptr && rv[l]->SectionName->Equals(".text"))
				PatchLoc = (aSection->Misc.VirtualSize + aSection->VirtualAddress) - 4;

			rv[l]->CLRPatch = PatchLoc;
		}

		rv[0] = Header = gcnew CLR_PE_SECTIONS;
		Header->CfgFlag = cfgOff;
		Header->DebugLoc = iDebugLoc;
		Header->DebugSize = iDebugSize;

		Header->ImportLoc = importLoc;
		Header->ImportSize = importSize;

		Header->StartOff = 0;
		Header->IsCLRApp = isCLR;
		Header->Is64bit = is64app;
		Header->CLRPatch = PatchLoc;
		Header->ImageBase = ImageBase;
		//Header->VirtualSize = rv[cnt-1]->StartOff + rv[cnt-1]->Length;
		Header->Length = HeaderSize;
		Header->SectionName = gcnew String("PE Header");
		Header->IsExec = true; // we define executable code and require values to be valid or else we could be fake'd out easially

							   // This also resolves the real image base, which needs to be "fixed" if the binary is relocated
		Header->TimeDateStamp = TimeDate;
		Header->VirtualSize = SizeOfImage;
		Header->CheckSum = CheckSum;
		Header->BaseOfCode = pntHeader->OptionalHeader.BaseOfCode;

		// were going to use page alignment for now on
		Header->PostPadAlign = ROUND_UP(Header->Length, 4096) - Header->Length;

		PIMAGE_DEBUG_DIRECTORY		pDebugDir;
		if (pntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size != 0)
		{
			pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)bp + Rva2Offset(pntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, pSection, pntHeader));
			pcv = (PCODEVIEW_HEADER)((PBYTE)bp + Rva2Offset(pDebugDir->AddressOfRawData, pSection, pntHeader));
			// get a GUID CV header
			if (pcv != NULL && !memcmp(pcv, "RSDS", 4))
			{
				Header->CV_AGE = pcv->Age;
				Header->CV_PDBNAME = gcnew String(pcv->PdbName);
				Header->CV_GUID = *reinterpret_cast<Guid *>(const_cast<GUID *>(&pcv->Guid));
			}
		}

		if (DoImports)
		{
			if (pntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
			{
				pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)bp + Rva2Offset(pntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSection, pntHeader));

				if (pImportDesc)
				{
					Header->ImportTable = gcnew Dictionary<String^, List<KeyValuePair<String^, unsigned __int64>>^>();
					String^ ModName = nullptr;
					String^ clrName = nullptr;
					__try
					{
						while (pImportDesc->Name)
						{
							ModName = gcnew String((char *)(bp + Rva2Offset(pImportDesc->Name, pSection, pntHeader)));
							List<KeyValuePair<String^, unsigned __int64>>^ ModImports = gcnew List<KeyValuePair<String^, unsigned __int64>>();
							KeyValuePair<String^, unsigned __int64> NameRVA;

							PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)pImportDesc->FirstThunk;
							PBYTE pHintName = bp;
							char *pAPIName = NULL;
							int x = 0;

							if (pImportDesc->OriginalFirstThunk != 0)
								pHintName += Rva2Offset(pImportDesc->OriginalFirstThunk, pSection, pntHeader);
							else
								pHintName += Rva2Offset(pImportDesc->FirstThunk, pSection, pntHeader);

							PIMAGE_THUNK_DATA pimage_thunk_data = (PIMAGE_THUNK_DATA)pHintName;
							while (pimage_thunk_data && pimage_thunk_data->u1.AddressOfData != 0)
							{
								unsigned __int64 dwAPIaddress = pimage_thunk_data->u1.AddressOfData;

								if ((dwAPIaddress & 0x8000000000000000) == 0x8000000000000000) {
									dwAPIaddress &= 0x7FFFFFFFffffFFFF;
									clrName = nullptr;
								}
								else {
									pAPIName = (char *)(bp + Rva2Offset(dwAPIaddress, pSection, pntHeader) + 2);
									clrName = gcnew String(pAPIName);
								}
								NameRVA = KeyValuePair<String^, unsigned __int64>(clrName, dwAPIaddress);
								ModImports->Add(NameRVA);

								thunk += 4;
								pHintName += 4;
								pimage_thunk_data++;
							}
							Header->ImportTable->Add(ModName, ModImports);
							pImportDesc++;
						}
					}
					__finally {}
				}
			}
		}
		return rv;
	}

	String^ GetSymPath(wchar_t *PEFile, bool RootModule)
	{
		wchar_t filePath[MAX_PATH * 3];
		marshal_context context;
		array<CLR_PE_SECTIONS^>^ PEsecs = nullptr;
		String^ ToScan = gcnew String(PEFile);
		String^ PDBName = ToScan->Substring(ToScan->LastIndexOf("\\") + 1, (ToScan->LastIndexOf(".") - 1) - ToScan->LastIndexOf("\\")) + ".pdb";
		const wchar_t* npdbName = context.marshal_as<const wchar_t*>(PDBName);

		PEsecs = IOAHook2::GetPESections(ToScan, false, true);
		if (RootModule)
			Globals::ScannedPE = PEsecs;

		if (PEsecs && PEsecs->Length > 1)
		{
			CLR_PE_SECTIONS^ PEhdr = PEsecs[0];
			// need to use symsrv to load imports
			DWORD TimeDateStamp = PEhdr->TimeDateStamp, SizeOfImage = PEhdr->VirtualSize;
			if (!SymFindFileInPath(GetCurrentProcess(), NULL, npdbName, &TimeDateStamp, SizeOfImage, 0, SSRVOPT_DWORDPTR, filePath, NULL, NULL))
			{
				const wchar_t* npdbNameCV = context.marshal_as<const wchar_t*>(PEhdr->CV_PDBNAME);
				array<Byte>^ GuidARR = PEhdr->CV_GUID.ToByteArray();
				pin_ptr<Byte>  pinnedGUID = &GuidARR[0];

				if (!SymFindFileInPath(GetCurrentProcess(), NULL, npdbNameCV, pinnedGUID, PEhdr->CV_AGE, 0, SSRVOPT_GUIDPTR, filePath, NULL, NULL))
					wprintf(L"Unable to locate symbols (TimeDate or GUID) for dependency module: 0x%x %s:%s\n", GetLastError(), PEFile, npdbName);
				else
					return gcnew String(filePath);
			}
			else
				return gcnew String(filePath);
		}
		return nullptr;
	}

	BOOL CALLBACK ScanCallback(PCTSTR FilePath, _In_opt_ PVOID  CallerData)
	{
		wchar_t PDBfilePath[MAX_PATH * 3];
		wchar_t PathDup[MAX_PATH * 3];

		int *index = (int *)CallerData;
		marshal_context context;
		CLR_PE_SECTIONS^ Hdr = Globals::PEImports[*index];

		const wchar_t* npdbName = context.marshal_as<const wchar_t*>(Hdr->CV_PDBNAME);
		array<Byte>^ GuidARR = Hdr->CV_GUID.ToByteArray();
		pin_ptr<Byte>  pinnedGUID = &GuidARR[0];

		DWORD TimeDateStamp = Hdr->TimeDateStamp, SizeOfImage = Hdr->VirtualSize;

		wcscpy(PathDup, FilePath);
		wchar_t* PathComponentEnd = wcsrchr(PathDup, L'\\');
		*PathComponentEnd = L'\0';

		if (!SymFindFileInPath(GetCurrentProcess(), PathDup, npdbName, &TimeDateStamp, SizeOfImage, 0, SSRVOPT_DWORDPTR, PDBfilePath, NULL, NULL))
		{
			// we should now have the CV/timestamp data for locating matching PDB's
			if (SymFindFileInPath(GetCurrentProcess(), PathDup, npdbName, pinnedGUID, Hdr->CV_AGE, 0, SSRVOPT_GUIDPTR, PDBfilePath, NULL, NULL))
			{
				Hdr->PDBPath = gcnew String(PDBfilePath);
				Console::WriteLine(" +++ MATCHED PDB for import DLL [" + Path::GetFileName(Hdr->FileName) + "] symbols [" + Hdr->PDBPath + "]");
				return true;
			}
			else
				wprintf(L"Candidate symbol did not match error %x\n", GetLastError());
		}
		else
		{
			Hdr->PDBPath = gcnew String(PDBfilePath);
			Console::WriteLine(" +++ MATCHED PDB for import DLL [" + Path::GetFileName(Hdr->FileName) + "] symbols [" + Hdr->PDBPath + "]");
			return true;
		}
		return false;
	}


	BOOL __clrcall mScanCallback(String^ FilePath, CLR_PE_SECTIONS^ Hdr)
	{
		wchar_t PDBfilePath[MAX_PATH * 3];
		wchar_t PathDup[MAX_PATH * 3];

		marshal_context context;

		const wchar_t* aFilePath = context.marshal_as<const wchar_t*>(FilePath);
		const wchar_t* npdbName = context.marshal_as<const wchar_t*>(Hdr->CV_PDBNAME);

		array<Byte>^ GuidARR = Hdr->CV_GUID.ToByteArray();
		pin_ptr<Byte>  pinnedGUID = &GuidARR[0];

		DWORD TimeDateStamp = Hdr->TimeDateStamp, SizeOfImage = Hdr->VirtualSize;

		wcscpy(PathDup, aFilePath);
		wchar_t* PathComponentEnd = wcsrchr(PathDup, L'\\');
		*PathComponentEnd = L'\0';

		if (!SymFindFileInPath(GetCurrentProcess(), PathDup, npdbName, &TimeDateStamp, SizeOfImage, 0, SSRVOPT_DWORDPTR, PDBfilePath, NULL, NULL))
		{
			// we should now have the CV/timestamp data for locating matching PDB's
			if (SymFindFileInPath(GetCurrentProcess(), PathDup, npdbName, pinnedGUID, Hdr->CV_AGE, 0, SSRVOPT_GUIDPTR, PDBfilePath, NULL, NULL))
			{
				Hdr->PDBPath = gcnew String(PDBfilePath);
				Console::WriteLine(" +++ MATCHED IMPORT " + Environment::NewLine +
					"[" + Hdr->FileName + "]" + Environment::NewLine +
					"[" + Hdr->PDBPath + "]");
				return true;
			}
			else if (!MinOutput)
				wprintf(L"Candidate symbol did not match error %x\n", GetLastError());
		}
		else
		{
			Hdr->PDBPath = gcnew String(PDBfilePath);
			Console::WriteLine(" +++ MATCHED IMPORT " + Environment::NewLine +
				"[" + Hdr->FileName + "]" + Environment::NewLine +
				"[" + Hdr->PDBPath + "]");
			return true;
		}
		return false;
	}

	void RecurAddDirs(String^ Folder, List<String^>^ SearchDirs)
	{
		for each(String^ dir in Directory::GetDirectories(Folder))
		{
			try {
				RecurAddDirs(dir, SearchDirs);
				SearchDirs->Add(dir);
			}
			catch (Exception^ catchException)
			{
				// ignore
				Debug::WriteLine("catchException:" + catchException->ToString());
			}
		}
	}

	List<String^>^ DependencyScanner(String^ PEtoScan, bool OnlyPE)
	{
		wchar_t envSymPath[8192];
		marshal_context context;
		List<String^>^ rv = gcnew List<String^>();
		const wchar_t* PESCAN = context.marshal_as<const wchar_t*>(PEtoScan);
		bool ModuleFound = false;
		bool SkipModule = false;
		bool MatchedPDB = false;

		List<String^>^ SearchPaths = gcnew List<String^>();
		List<String^>^ SearchModules = gcnew List<String^>();

		Globals::ScannedPE = IOAHook2::GetPESections(PEtoScan, false, true);
		CLR_PE_SECTIONS^ Hdr = Globals::ScannedPE[0];
		Globals::PEImports = gcnew List<CLR_PE_SECTIONS^>();

		//// build search paths
		wchar_t *pwc = NULL;
		SymGetSearchPath(GetCurrentProcess(), envSymPath, sizeof(envSymPath) / sizeof(wchar_t));
		pwc = wcstok(envSymPath, L"*;");
		while (pwc != NULL)
		{
			SearchPaths->Add(gcnew String(pwc));
			pwc = wcstok(NULL, L"*;");
		}
		/////
		// build table of all accessible folders
		// only have to do this since enumeratefiles() will break if it hit's an exception
		List<String^>^ SearchDirs = gcnew List<String^>();
		for each(String^ Folder in SearchPaths)
		{
			if (!Globals::NoRecurDependencyScan && Directory::Exists(Folder))
			{
				SearchDirs->Add(Folder);
				RecurAddDirs(Folder, SearchDirs);
			}
		}

		String^ SymPath = GetSymPath((wchar_t*)PESCAN, true);
		if (SymPath != nullptr) {
			rv->Add(SymPath);
			if (OnlyPE)
				return rv;
		}
		else
		{
			// no Symbols found for main module
			// add it to the search queue
			SearchModules->Add(Path::GetFileName(PEtoScan));
		}

		if (!OnlyPE)
			SearchModules->AddRange(Hdr->ImportTable->Keys);

		for each(String^ Module in SearchModules)
		{
			SkipModule = false;
			for each(String^ BannedMod in Globals::ModulesNotToHook)
				if (BannedMod->ToUpper()->Contains(Module->ToUpper()))
					SkipModule = true;

			if (SkipModule)
				continue;

			const wchar_t* nModule = context.marshal_as<const wchar_t*>(Module);

			if (!MinOutput)
				wprintf(L"Scanning for PE %s\n", nModule);
			//wprintf(L"Scanning %s\n", envSymPath);
			MatchedPDB = false;

			for each(String^ SearchPath in SearchDirs)
			{
				for each(String^ FullModulePath in Directory::GetFiles(SearchPath, Module, SearchOption::TopDirectoryOnly))
				{
					// extract PDB binding info
					array<CLR_PE_SECTIONS^>^ LocatedDependency = IOAHook2::GetPESections(FullModulePath, false, true);
					if (LocatedDependency != nullptr && LocatedDependency->Length > 1)
					{
						if (!MinOutput)
							Console::WriteLine("Found a requested PE scanning for matching PDB for " + FullModulePath);
						CLR_PE_SECTIONS^ PEhdr = LocatedDependency[0];

						const wchar_t* npdbName = context.marshal_as<const wchar_t*>(PEhdr->CV_PDBNAME);
						array<Byte>^ GuidARR = PEhdr->CV_GUID.ToByteArray();
						pin_ptr<Byte>  pinnedGUID = &GuidARR[0];

						for each(String^ FullPDBPath in Directory::GetFiles(SearchPath, Module, SearchOption::TopDirectoryOnly))
						{
							// find PDB
							if (mScanCallback(FullPDBPath, PEhdr))
							{
								MatchedPDB = true;
								rv->Add(PEhdr->PDBPath);
								Globals::PEImports->Add(PEhdr);
								break;
							}
						}
					}
					if (MatchedPDB)
						break;
				}
				if (MatchedPDB)
					break;
			}

			ConsoleColor fc = Console::ForegroundColor;
			if (!MatchedPDB) {
				Console::ForegroundColor = ConsoleColor::Red;
				Console::WriteLine("Failed for dependency: " + Module);
			}
			Console::ForegroundColor = fc;

			if (!OnlyPE && !MinOutput && MatchedPDB)
				for each(KeyValuePair<String^, unsigned __int64> kvp in Hdr->ImportTable[Module])
					Console::WriteLine("\t" + kvp.Key + " @ 0x" + kvp.Value.ToString("X"));
		}
		return rv;
	}
#endif
}