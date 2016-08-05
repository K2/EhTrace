#include "stdafx.h"

#include <set>

void _DumpContext(PExecutionBlock pXblock);

BlockFighters **FightList;

BlockFighters staticList[] = {
	{ NULL, "RoP Fighter", DEFENSIVE_MOVE, ROP_FIGHTER, NULL, RoPFighter },
	{ NULL, "Encryption Escrow Fighter", DEFENSIVE_MOVE, ESCROW_FIGHTER, InitKeyFighter, KeyFighter }
	//{ NULL, "EnableDisable", DEFENSIVE_MOVE, ESCROW_FIGHTER, InitDisableFighter, KeyFighter }
};
int FighterCount = sizeof(staticList)/sizeof(staticList[0]);


void ConfigureFighters(BlockFighters **Fighters, int cnt)
{
	FightList = Fighters;
	FighterCount = cnt;
}


void InitFighters()
{
	if (FightList == NULL)
	{
		for (int i = 0; i < FighterCount; i++)
		{
			if (staticList[i].InitFighter)
				staticList[i].InitFighter();
		}
	}
	else {
		for (int i = 0; i < FighterCount; i++)
		{
			if (FightList[i] && FightList[i]->InitFighter)
				FightList[i]->InitFighter();
		}
	}
}

void Fight(PExecutionBlock pCtx)
{
	if (FightList == NULL)
	{
		for (int i = 0; i < FighterCount; i++)
		{
			if (staticList[i].Fighter)
				staticList[i].Fighter(pCtx);
		}
	}
	else {
		for (int i = 0; i < FighterCount; i++)
		{
			if (FightList[i] && FightList[i]->Fighter)
				FightList[i]->Fighter(pCtx);
		}
	}
}