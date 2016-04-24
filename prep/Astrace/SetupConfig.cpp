#include "stdafx.h"
#include "../../EhTrace/Config.h"

PConfigContext pConfig = NULL;
ULONG64 ConfigSize;


int CreateConfig()
{
	pConfig = (PConfigContext) ConnectConfig();
	memset(pConfig, 0, sizeof(ConfigContext));

	return 0;

}