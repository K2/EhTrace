#pragma once


// Some self-defense techniques would be needed in a real sandbox... were a fairly loose box in that regard
// 
// What about force code to calculate some constants we know that can be scanned for async in non-blocking threads or IO co-routines
//  
// Not blocking the current block (Blocks4LIF3!) is nice but dangerous, having a mix of async and sync checks seems required !:S
// * Cache accelerate self-defending checks that are only one time
// * Establish bit's in logging structure to indicate fighter tripped...
// 
//  TODO: ContinueHandler



#define DEFENSIVE_MOVE 1
#define OFFENSIVE_MOVE 2
#define NO_FIGHTER 0
#define ROP_FIGHTER 1
#define ESCROW_FIGHTER 2
#define AFL_FLIGHTER 4

// Fighter ideas
// Stale Pointer on Free
// adapt ASAN/TSAN
// 
// mini heap sanity/pageheap on the fly
// 
typedef void FighterFunc(void* pCtx);
typedef void InitFighterFunc();

typedef struct _BlockFighters
{
	char *Module;
	char *Name; 
	int Move; 
	int Type; 
	InitFighterFunc *InitFighter; 
	FighterFunc *Fighter;
} BlockFighters, *PBlockFighters;
extern BlockFighters **FightList;

extern HookInfo HooksConfig[];
extern int HookCount;
