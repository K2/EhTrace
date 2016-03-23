// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_WCSTOK
#define DBGHELP_TRANSLATE_TCHAR

#include <stdio.h>
#include <tchar.h>

#include <stdlib.h>
#include <string.h>

#include <windows.h>  // basic types/wtypes.h include

#include <DbgHelp.h>
#include "dia2.h"	

#include <iostream>
#include "OaIdl.h"

#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>

#include <stdlib.h>
#include <string.h>
#include <msclr\marshal.h>

#include <capstone/capstone.h>

#using <System.dll>
#using <System.Xml.dll>
#using <System.Xml.Linq.dll>


#define ROUND_UP(value, modulus)\
  ((modulus) & ((modulus) - 1) ?	/* not a power of 2 */\
	((value) + ((modulus) - 1)) / ((modulus) * (modulus)) :\
	((value) + ((modulus) - 1)) & -(modulus))

using namespace System;
using namespace System::IO;
using namespace msclr::interop;
using namespace System::Collections::Generic;
using namespace System::Text;
using namespace System::Xml;
using namespace System::Xml::Linq;
using namespace System::Diagnostics;
using namespace System::Runtime::Serialization;
using namespace System::Runtime::Serialization::Formatters::Binary;
using namespace System::Text::RegularExpressions;
using namespace System::Threading::Tasks;
using namespace System::Collections::Concurrent;

