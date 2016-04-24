#include "stdafx.h"
#pragma once

namespace AStrace {
	public ref class SymbolSetup abstract
	{
	public:
		static void SymSetup(PPROCESS_INFORMATION pi);
	};
}