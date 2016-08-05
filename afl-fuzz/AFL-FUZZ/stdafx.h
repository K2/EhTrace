// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once
#define _CRT_SECURE_NO_WARNINGS 
#include "targetver.h"

#include <tchar.h>



#define AFL_MAIN
#define MESSAGES_TO_STDOUT

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#define _CRT_RAND_S
#include <windows.h>
#include <Shellapi.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <stdarg.h>
#include <io.h>
#include <direct.h>


#define VERSION "1.96b"

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)
#  include <sys/sysctl.h>
#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */


/* Lots of globals, but mostly for the status UI and other things where it
really makes no sense to haul them around as function parameters. */

static u8 *in_dir,                    /* Input directory with test cases  */
*out_file,                  /* File to fuzz, if any             */
*out_dir,                   /* Working & output directory       */
*sync_dir,                  /* Synchronization directory        */
*sync_id,                   /* Fuzzer ID                        */
*use_banner,                /* Display banner                   */
*in_bitmap,                 /* Input bitmap                     */
*doc_path,                  /* Path to documentation dir        */
*target_path,               /* Path to target binary            */
*target_cmd,                /* command line of target           */
*orig_cmdline;              /* Original command line            */

static u32 exec_tmout = EXEC_TIMEOUT; /* Configurable exec timeout (ms)   */
static u64 mem_limit = MEM_LIMIT;     /* Memory cap for child (MB)        */

static u32 stats_update_freq = 1;     /* Stats update frequency (execs)   */

static u8  skip_deterministic,        /* Skip deterministic stages?       */
force_deterministic,       /* Force deterministic stages?      */
use_splicing,              /* Recombine input files?           */
dumb_mode,                 /* Run in non-instrumented mode?    */
score_changed,             /* Scoring for favorites changed?   */
kill_signal,               /* Signal that killed the child     */
resuming_fuzz,             /* Resuming an older fuzzing job?   */
timeout_given,             /* Specific timeout given?          */
not_on_tty,                /* stdout is not a tty              */
term_too_small,            /* terminal dimensions too small    */
uses_asan,                 /* Target uses ASAN?                */
no_forkserver,             /* Disable forkserver?              */
crash_mode,                /* Crash mode! Yeah!                */
in_place_resume,           /* Attempt in-place resume?         */
auto_changed,              /* Auto-generated tokens changed?   */
no_cpu_meter_red,          /* Feng shui on the status screen   */
no_var_check,              /* Don't detect variable behavior   */
shuffle_queue,             /* Shuffle input queue?             */
bitmap_changed = 1,        /* Time to update bitmap?           */
qemu_mode,                 /* Running in QEMU mode?            */
skip_requested,            /* Skip request, via SIGUSR1        */
run_over10m;               /* Run time over 10 minutes?        */

static s32 out_fd,                    /* Persistent fd for out_file       */
dev_urandom_fd = -1,       /* Persistent fd for /dev/urandom   */
dev_null_fd = -1,          /* Persistent fd for /dev/null      */
fsrv_ctl_fd,               /* Fork server control pipe (write) */
fsrv_st_fd;                /* Fork server status pipe (read)   */




static u8* trace_bits;                /* SHM with instrumentation bitmap  */

static u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */
virgin_hang[MAP_SIZE],     /* Bits we haven't seen in hangs    */
virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */

static HANDLE shm_handle;             /* Handle of the SHM region         */
static HANDLE pipe_handle;            /* Handle of the name pipe          */

static volatile u8 stop_soon,         /* Ctrl-C pressed?                  */
clear_screen = 1,  /* Window resized?                  */
child_timed_out;   /* Traced process timed out?        */

static u32 queued_paths,              /* Total number of queued testcases */
queued_variable,           /* Testcases with variable behavior */
queued_at_start,           /* Total number of initial inputs   */
queued_discovered,         /* Items discovered during this run */
queued_imported,           /* Items imported via -S            */
queued_favored,            /* Paths deemed favorable           */
queued_with_cov,           /* Paths with new coverage bytes    */
pending_not_fuzzed,        /* Queued but not done yet          */
pending_favored,           /* Pending favored paths            */
cur_skipped_paths,         /* Abandoned inputs in cur cycle    */
cur_depth,                 /* Current path depth               */
max_depth,                 /* Max path depth                   */
useless_at_start,          /* Number of useless starting paths */
current_entry,             /* Current queue entry ID           */
havoc_div = 1;             /* Cycle count divisor for havoc    */

static u64 total_crashes,             /* Total number of crashes          */
unique_crashes,            /* Crashes with unique signatures   */
total_hangs,               /* Total number of hangs            */
unique_hangs,              /* Hangs with unique signatures     */
total_execs,               /* Total execve() calls             */
start_time,                /* Unix start time (ms)             */
last_path_time,            /* Time for most recent path (ms)   */
last_crash_time,           /* Time for most recent crash (ms)  */
last_hang_time,            /* Time for most recent hang (ms)   */
queue_cycle,               /* Queue round counter              */
cycles_wo_finds,           /* Cycles without any new paths     */
trim_execs,                /* Execs done to trim input files   */
bytes_trim_in,             /* Bytes coming into the trimmer    */
bytes_trim_out,            /* Bytes coming outa the trimmer    */
blocks_eff_total,          /* Blocks subject to effector maps  */
blocks_eff_select;         /* Blocks selected as fuzzable      */

static u32 subseq_hangs;              /* Number of hangs in a row         */

static u8 *stage_name = (u8 *) "init",       /* Name of the current fuzz stage   */
*stage_short,               /* Short stage name                 */
*syncing_party;             /* Currently syncing with...        */

static s32 stage_cur, stage_max;      /* Stage progression                */
static s32 splicing_with = -1;        /* Splicing with which test case?   */

static u32 syncing_case;              /* Syncing with case #...           */

static s32 stage_cur_byte,            /* Byte offset of current stage op  */
stage_cur_val;             /* Value used for stage op          */

static u8  stage_val_type;            /* Value type (STAGE_VAL_*)         */

static u64 stage_finds[32],           /* Patterns found per fuzz stage    */
stage_cycles[32];          /* Execs per fuzz stage             */

static u32 rand_cnt;                  /* Random number counter            */

static u64 total_cal_us,              /* Total calibration time (us)      */
total_cal_cycles;          /* Total calibration cycles         */

static u64 total_bitmap_size,         /* Total bit count for all bitmaps  */
total_bitmap_entries;      /* Number of bitmaps counted        */

static u32 cpu_core_count;            /* CPU core count                   */

static FILE* plot_file;               /* Gnuplot output file              */

struct queue_entry {

	u8* fname;                          /* File name for the test case      */
	u32 len;                            /* Input length                     */

	u8  cal_failed,                     /* Calibration failed?              */
		trim_done,                      /* Trimmed?                         */
		was_fuzzed,                     /* Had any fuzzing done yet?        */
		passed_det,                     /* Deterministic stages passed?     */
		has_new_cov,                    /* Triggers new coverage?           */
		var_behavior,                   /* Variable behavior?               */
		favored,                        /* Currently favored?               */
		fs_redundant;                   /* Marked as redundant in the fs?   */

	u32 bitmap_size,                    /* Number of bits set in bitmap     */
		exec_cksum;                     /* Checksum of the execution trace  */

	u64 exec_us,                        /* Execution time (us)              */
		handicap,                       /* Number of queue cycles behind    */
		depth;                          /* Path depth                       */

	u8* trace_mini;                     /* Trace bytes, if kept             */
	u32 tc_ref;                         /* Trace bytes ref count            */

	struct queue_entry *next,           /* Next element, if any             */
		*next_100;       /* 100 elements ahead               */

};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
*queue_cur, /* Current offset within the queue  */
*queue_top, /* Top of the list                  */
*q_prev100; /* Previous 100 marker              */

static struct queue_entry*
top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */

struct extra_data {
	u8* data;                           /* Dictionary token data            */
	u32 len;                            /* Dictionary token length          */
	u32 hit_cnt;                        /* Use count in the corpus          */
};

static struct extra_data* extras;     /* Extra tokens to fuzz with        */
static u32 extras_cnt;                /* Total number of tokens read      */

static struct extra_data* a_extras;   /* Automatically selected extras    */
static u32 a_extras_cnt;              /* Total number of tokens available */

static u8* (*post_handler)(u8* buf, u32* len);

/* Interesting values, as per config.h */

static s8  interesting_8[] = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

/* Fuzzing stages */

enum {
	/* 00 */ STAGE_FLIP1,
	/* 01 */ STAGE_FLIP2,
	/* 02 */ STAGE_FLIP4,
	/* 03 */ STAGE_FLIP8,
	/* 04 */ STAGE_FLIP16,
	/* 05 */ STAGE_FLIP32,
	/* 06 */ STAGE_ARITH8,
	/* 07 */ STAGE_ARITH16,
	/* 08 */ STAGE_ARITH32,
	/* 09 */ STAGE_INTEREST8,
	/* 10 */ STAGE_INTEREST16,
	/* 11 */ STAGE_INTEREST32,
	/* 12 */ STAGE_EXTRAS_UO,
	/* 13 */ STAGE_EXTRAS_UI,
	/* 14 */ STAGE_EXTRAS_AO,
	/* 15 */ STAGE_HAVOC,
	/* 16 */ STAGE_SPLICE
};

/* Stage value types */

enum {
	/* 00 */ STAGE_VAL_NONE,
	/* 01 */ STAGE_VAL_LE,
	/* 02 */ STAGE_VAL_BE
};

/* Execution status fault codes */

enum {
	/* 00 */ FAULT_NONE,
	/* 01 */ FAULT_HANG,
	/* 02 */ FAULT_CRASH,
	/* 03 */ FAULT_ERROR,
	/* 04 */ FAULT_NOINST,
	/* 05 */ FAULT_NOBITS
};

