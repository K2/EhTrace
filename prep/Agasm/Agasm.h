// Agasm.h

#pragma once

using namespace System;

namespace Agasm {


	public ref class CLR_PE_SECTIONS {
	public:
		UInt64	RelocatedBase;
		UInt64	ImageBase;
		UInt64 	StartOff;
		UInt32 	Length;
		UInt32	VirtualSize;
		UInt32	CLRPatch;
		UInt32	TimeDateStamp;
		UInt32	CheckSum;
		UInt32  DebugLoc;
		UInt32  DebugSize;
		Int32	PrePadAlign;
		Int32	PostPadAlign;
		UInt32  ImportLoc;
		UInt32	ImportSize;
		UInt32	BaseOfCode;
		UInt32	CfgFlag;
		bool	IsCLRApp;
		bool	IsCode;
		bool	IsExec;
		bool	IsWriteable;
		bool	IsNoAccess;
		bool	IsRead;
		bool	IsWriteCopy;
		bool	IsNoCache;
		bool	IsVadSection;
		bool	IsModule;
		bool	Is64bit;
		String^ SectionName;
		String^ PDBPath; // verified matching
		String^ FileName;
		// just copy in the needful data into managed space instead of destructor/finalize/native ptr
		Guid CV_GUID = Guid::Empty;
		String^ CV_PDBNAME;
		unsigned int CV_AGE;

		Dictionary<String^, List<KeyValuePair<String^, unsigned __int64>>^>^ ImportTable;

		// array<CLR_RELOC_INFO^>^ Relocs;  not needed here
		//IntPtr  cvHeader = IntPtr::Zero;
		// IDisposeable is not directly callable, the !class method causes the compiler to emit it
		/*
		__clrcall !CLR_PE_SECTIONS()
		{
			if (cvHeader != IntPtr::Zero)
			{
				void *vp = static_cast<void *>(cvHeader);
				if (vp != NULL)
				free(vp);
			}
		}

		protected:

		// destructor forwards to the disposable interface
		virtual __clrcall ~CLR_PE_SECTIONS()
		{
			this->!CLR_PE_SECTIONS();
		}

		*/
	};


	static array<CLR_PE_SECTIONS^>^ GetPESections(Stream^ File);
	array<CLR_PE_SECTIONS^>^ GetPESections(String^ File, bool UseVA, bool DoImports);
	array<CLR_PE_SECTIONS^>^ GetPESections(BYTE *bp, int Max, bool UseVA, bool DoImports, ULONGLONG OrigImageBase);
	List<String^>^ DependencyScanner(String^ PEtoScan, bool OnlyEXE);

	public ref class DataInfo
	{
	public:
		String^		Name;
		String^		Type;

		void SetType(DWORD symTag)
		{
			switch (symTag)
			{
			case SymTagNull:
				Type = "NULL";
				break;
			case SymTagExe:
				Type = "Exe";
				break;
			case SymTagCompiland:
				Type = "Compiland";
				break;
			case SymTagCompilandDetails:
				Type = "SymTagCompilandDetails";
				break;
			case SymTagCompilandEnv:
				Type = "SymTagCompilandEnv";
				break;
			case SymTagFunction:
				Type = "Function";
				break;
			case SymTagBlock:
				Type = "SymTagBlock";
				break;
			case SymTagAnnotation:
				Type = "Annotation";
				break;
			case SymTagLabel:
				Type = "SymTagLabel";
				break;
			case SymTagPublicSymbol:
				Type = "SymTagPublicSymbol";
				break;
			case SymTagUDT:
				Type = "UDT";
				break;
			case SymTagEnum:
				Type = "SymTagEnum";
				break;
			case SymTagFunctionType:
				Type = "FunctionType";
				break;
			case SymTagPointerType:
				Type = "Pointer";
				break;
			case SymTagArrayType:
				Type = "Array";
				break;
			case SymTagBaseType:
				Type = "Base";
				break;
			case SymTagTypedef:
				Type = "Typedef";
				break;
			case SymTagBaseClass:
				Type = "BaseClass";
				break;
			case SymTagFriend:
				Type = "Friend";
				break;
			case SymTagFunctionArgType:
				Type = "FunctionArgType";
				break;
			case SymTagFuncDebugStart:
				Type = "FuncDebugStart";
				break;
			case SymTagFuncDebugEnd:
				Type = "FuncDebugEnd";
				break;
			case SymTagUsingNamespace:
				Type = "UsingNamespace";
				break;
			case SymTagVTableShape:
				Type = "gVTableShape";
				break;
			case SymTagVTable:
				Type = "VTable";
				break;
			case SymTagCustom:
				Type = "Custom";
				break;
			case SymTagThunk:
				Type = "Thunk";
				break;
			case SymTagCustomType:
				Type = "CustomType";
				break;
			case SymTagManagedType:
				Type = "gManagedType";
				break;
			case SymTagDimension:
				Type = "Dimension";
				break;
			case SymTagCallSite:
				Type = "CallSite";
				break;
			case SymTagInlineSite:
				Type = "InlineSite";
				break;
			case SymTagBaseInterface:
				Type = "BaseInterface";
				break;
			case SymTagVectorType:
				Type = "Vector";
				break;
			case SymTagMatrixType:
				Type = "Matrix";
				break;
			case SymTagHLSLType:
				Type = "HLSL";
				break;
			default:
				Type = "UNKNOWN";
				break;
			}
		}
	};
	[System::SerializableAttribute]
	public ref class CompileDetails
	{
	public:
		String^ Module;
		String^ Language;
		String^ Cpu;
		bool	IsManaged;
		bool	IsHotPatch;
		bool	IsGS;
		bool	IsSDL;
		bool	IsNoDebuug;
	};

	public ref class BasicSymInfo
	{
	public:
		BasicSymInfo() {}
		BasicSymInfo(String^ name)
		{
			Name = name;
		}
		BasicSymInfo(String^ name, unsigned __int64 VA)
		{
			Name = name;
			VirtualAddress = VA;
		}
		String^ Name;
		unsigned __int64 VirtualAddress;
		unsigned int RVA;
		unsigned int AddressOffset;
		unsigned int AddressSection;
		unsigned __int64 Length;
	};
	ref class DissassembledFunc;

	[System::SerializableAttribute]
	public ref class FuncInfo : public ICloneable, IComparable
	{
	private:
		String^ _name;
		DissassembledFunc^ _dissData;

		void CopyData(FuncInfo% From, FuncInfo^ To)
		{
			To = static_cast<FuncInfo^>(From.MemberwiseClone());
			To->ArgNames = gcnew List<String^>(static_cast<array<String^>^>(From.ArgNames->ToArray()->Clone()));
			To->ArgCount = From.ArgCount;
			To->Name = From.Name;
			To->UDName = From.UDName;
			To->VirtualAddress = From.VirtualAddress;
			To->RVA = From.RVA;
			To->ID = From.ID;
			To->Length = From.Length;
			To->AddressOffset = From.AddressOffset;
			To->IsFunc = From.IsFunc;
		}
	public:
		FuncInfo(FuncInfo^ From)
		{
			CopyData(*From, this);
		}
		FuncInfo(FuncInfo% From)
		{
			CopyData(From, this);
		}
		FuncInfo() {}
		virtual int __clrcall CompareTo(Object^ obj) sealed
		{
			if (obj == nullptr) return 1;

			FuncInfo^ other = static_cast<FuncInfo^>(obj);
			if (other != nullptr)
				return this->VirtualAddress.CompareTo(other->VirtualAddress);
			else
				throw gcnew ArgumentException("Object is not a FuncInfo");
		}

		// Clone(other);
		System::Object^ Clone(System::Object^ apObj)
		{
			MemoryStream^ ms = gcnew MemoryStream();
			BinaryFormatter^ bf = gcnew BinaryFormatter();
			bf->Serialize(ms, apObj);
			ms->Position = 0;
			System::Object^ obj = bf->Deserialize(ms);
			ms->Close();
			return obj;
		}
		// this->Clone();
		virtual System::Object^ Clone(void)
		{
			MemoryStream^ ms = gcnew MemoryStream();
			BinaryFormatter^ bf = gcnew BinaryFormatter();
			bf->Serialize(ms, this);
			ms->Position = 0;
			System::Object^ obj = bf->Deserialize(ms);
			ms->Close();
			return obj;
		}
		unsigned int ID;

		virtual property String^ Name {
			String^ get() sealed { return _name; }
			void set(String^ Name) sealed { _name = Name; }
		}

		List<FuncInfo^>^ CallSites;
		List<FuncInfo^>^ Calls;
		List<String^>^ ArgNames;
		CompileDetails^	Compiler;
		String^ BlockName;
		String^ InModule;
		String^ UDName;
		String^ HookDoubtfull;
		String^ InfoLine;

		virtual property DissassembledFunc^ DissData {
			DissassembledFunc^ get() sealed { return _dissData; }
			void set(DissassembledFunc^ Name) sealed { _dissData = Name; }
		}

		int ArgCount;

		bool CustomCallingConv;
		bool IsInlined;
		bool IsNaked;
		bool NotReachable;
		bool IsPublic;
		bool IsThunk;
		bool IsPtr;
		bool IsFunc;

		unsigned int RVA;
		unsigned int AddressOffset;
		unsigned int AddressSection;

		unsigned __int64 VirtualAddress;
		unsigned __int64 Length;
	};


	public ref class ClassInfo
	{
	public:
		unsigned int	ID;
		unsigned int	ParentID;
		unsigned int	LexicalParentId;
		unsigned int	VirtualTableShapeID;
		unsigned int	SubTypeId;
		unsigned int	ThisAdjust;
		unsigned __int64 VTablePtrSize;
		unsigned __int64 VTableSize;
		unsigned int	VTableIndex;
		unsigned int	VTableOffset;

		String^			Name;
		String^			TypeName;
		String^			Parent;
		String^			LexicalParent;
		String^			VirtualBaseTableType;
		String^			BaseType;

		List<ClassInfo^>^	Children;
		List<DataInfo^>^	DataMembers;

		bool			IsIndirectVirtualBaseClass;
		bool			IsVirtualBaseClass;
		bool			IsVirtualInheritance;
		bool			IsMultipleInheritance;
		bool			IsSingleInheritance;
		bool			IsBaseClass;
		bool			IsVTable;
		bool			IsUserClass;
		bool			IsFriendClass;
		bool			HasDataMembers;
	};

	public ref class DissContext
	{
		String^ module;
	public:
		SortedDictionary<String^, SortedDictionary<unsigned int, FuncInfo^>^>^ FunctionTable;
		PBYTE	ModMapp;
		ULONGLONG VABase;
		ULONGLONG Length;
		String^	ASMOutFile;
		FILE	*fo;
		bool	BlockMode;
		bool	FlatMode;
		virtual property String^ Module {
			String^ get() sealed { return module; }
			void set(String^ Name) sealed { module = Name; }
		}
		virtual String^ __clrcall ToString() override sealed
		{
			// TODO: add more data 
			return Path::GetFileName(Module);
		}
	};

	int getopt(int argc, wchar_t **argv, wchar_t *opts);
	PBYTE GetBytesFromRVAMappedPE(ULONGLONG RVA, BYTE *PE);
	PBYTE MapFile(String ^File);
	void GenerateDissassembly(String^ Module, PBYTE ModMapp, ULONGLONG VABase, FILE* fo);
	void ManageDissassembly(DissContext^ Dctx);

	// global in C++/CLI 
	// not at all thread safe
	public ref class Globals abstract sealed {
	public:
		static DissContext^ DissCtx;
		static List<CLR_PE_SECTIONS^>^ PEImports;

		static array<CLR_PE_SECTIONS^>^ ScannedPE;
		static Dictionary<unsigned int, ClassInfo^>^ ClassTable;

		static List<unsigned __int64>^ PendingBlocks;

		static SortedDictionary<String^, SortedDictionary<unsigned int, FuncInfo^>^>^ FunctionTable;
		static SortedDictionary<String^, SortedDictionary<unsigned long long, BasicSymInfo^>^>^ BasicSymInfoTable;
		static SortedDictionary<unsigned long long, BasicSymInfo^>^ CurrBasicInfoModule;

		static array<KeyValuePair<unsigned int, FuncInfo^>>^ FunctionTableArray;

		static Dictionary<String^, CompileDetails^>^ UnassignedDetails;

		static List<String^>^ ModulesNotToHook;
		static List<String^>^ PrefixBanList;
		static List<String^>^ GlobBanList;
		static List<String^>^ HookOnlyFuncs;
		static List<String^>^ HookWildFuncs;
		static List<String^>^ HotWireFunctions;

		static SortedDictionary<Tuple<unsigned __int64, FuncInfo^>^, Tuple<unsigned __int64, String^>^>^ EdgeList;

		static bool NoRecurDependencyScan;
	};
}