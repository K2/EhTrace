#pragma once


#define FLAGS_POST	1
#define FLAGS_PRE	2
#define FLAGS_RESOLVE 4 // disassemble past 1 instruction to get where static linkers join

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
	ULONG Flags;                    //Reserved.
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
	PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG Flags;                    //Reserved.
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
	PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;
typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK LdrDllNotification)(ULONG NotificationReason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context);
typedef ULONG(__stdcall *LdrRegisterDllNotification)(ULONG FLAGS, LdrDllNotification *pNotify, PVOID CONTEXT, PVOID *Cookie);

typedef struct _NativeSymbol
{
	unsigned long long Address;
	unsigned long long Length;
	int NameLen;
	int UDNameLen;
	// mangled 
	const wchar_t* Name;
	// if un-mangled 
	const wchar_t* UDName;
} NativeSymbol, *PNativeSymbol;

typedef struct _ConfigContext
{
	unsigned long long SymCnt;
	PNativeSymbol SymTab;
	bool BasicSymbolsMode;
} ConfigContext, *PConfigContext;







//////////////// DR THUNKS
#define WINDOWS true
#define MAXIMUM_PATH      260


#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define X64 

typedef unsigned char* app_pc;
typedef unsigned __int64 uint64;
typedef unsigned __int32 uint32;
typedef unsigned __int32 uint;
typedef unsigned __int16 ushort;

typedef void(*generic_func_t) ();

#define DR_EXPORT extern "C" 

typedef uint client_id_t;
typedef unsigned __int64 ptr_uint_t;
typedef ptr_uint_t thread_id_t;
typedef ptr_uint_t process_id_t;

#define DR_ASSERT_MSG ;// NOP!
typedef HANDLE file_t;
/** The sentinel value for an invalid file_t. */
#  define INVALID_FILE INVALID_HANDLE_VALUE
/* dr_get_stdout_file and dr_get_stderr_file return errors as
* INVALID_HANDLE_VALUE.  We leave INVALID_HANDLE_VALUE as is,
* since it equals INVALID_FILE
*/
/*
#  define STDOUT (dr_get_stdout_file())
#  define STDERR (dr_get_stderr_file())
#  define STDIN  (dr_get_stdin_file())
*/


typedef struct _module_names_t {
	const char *module_name; /**< On windows this name comes from the PE header exports
							 * section (NULL if the module has no exports section).  On
							 * Linux the name will come from the ELF DYNAMIC program
							 * header (NULL if the module has no SONAME entry). */
	const char *file_name; /**< The file name used to load this module. Note - on Windows
						   * this is not always available. */
	const char *exe_name; /**< If this module is the main executable of this process then
						  * this is the executable name used to launch the process (NULL
						  * for all other modules). */
	const char *rsrc_name; /**< The internal name given to the module in its resource
						   * section. Will be NULL if the module has no resource section
						   * or doesn't set this field within it. */
} module_names_t;
typedef union _version_number_t {
	uint64 version;  /**< Representation as a 64-bit integer. */
	struct {
		uint ms;     /**< */
		uint ls;     /**< */
	} version_uint;  /**< Representation as 2 32-bit integers. */
	struct {
		ushort p2;   /**< */
		ushort p1;   /**< */
		ushort p4;   /**< */
		ushort p3;   /**< */
	} version_parts; /**< Representation as 4 16-bit integers. */
} version_number_t;

typedef struct _module_data_t {
	union {
		app_pc start; /**< starting address of this module */
		HMODULE handle; /**< module_handle for use with dr_get_proc_address() */
	}; /* anonymous union of start address and module handle */
	   /**
	   * Ending address of this module.  If the module is not contiguous
	   * (which is common on MacOS, and can happen on Linux), this is the
	   * highest address of the module, but there can be gaps in between start
	   * and end that are either unmapped or that contain other mappings or
	   * libraries.   Use the segments array to examine each mapped region,
	   * and use dr_module_contains_addr() as a convenience routine, rather than
	   * checking against [start..end).
	   */
	app_pc end;

	app_pc entry_point; /**< entry point for this module as specified in the headers */

	uint flags; /**< Reserved, set to 0 */

	module_names_t names; /**< struct containing name(s) for this module; use
						  * dr_module_preferred_name() to get the preferred name for
						  * this module */

	char *full_path; /**< full path to the file backing this module */
	version_number_t file_version; /**< file version number from .rsrc section */
	version_number_t product_version; /**< product version number from .rsrc section */
	uint checksum; /**< module checksum from the PE headers */
	uint timestamp; /**< module timestamp from the PE headers */
	size_t module_internal_size; /**< module internal size (from PE headers SizeOfImage) */
	BOOL contiguous;   /**< whether there are no gaps between segments */
	uint num_segments; /**< number of segments */
					   /**
					   * Array of num_segments entries, one per segment.  The array is sorted
					   * by the start address of each segment.
					   */
	//module_segment_data_t *segments;
//	uint timestamp;              /**< Timestamp from ELF Mach-O headers. */
} module_data_t, *Pmodule_data_t;

typedef struct {
	uint black_box_uint[26];
} instr_t;

struct _instr_list_t {
	instr_t *first;
	instr_t *last;
	int flags;
	app_pc translation_target;
#ifdef CLIENT_INTERFACE
	/* i#620: provide API for setting fall-throught/return target in bb */
	/* XXX: can this be unioned with traslation_target for saving space?
	* looks no, as traslation_target will be used in mangle and trace,
	* which conflicts with our checks in trace and return address mangling.
	* XXX: There are several possible ways to implement i#620, for example,
	* adding a dr_register_bb_event() OUT param.
	* However, we do here to avoid breaking backward compatibility
	*/
	app_pc fall_through_bb;
#endif /* CLIENT_INTERFACE */
}; /* instrlist_t */


#define UNKNOWN_MODULE_ID USHRT_MAX

static uint verbose;

#define NOTIFY(level, fmt, ...) do {          \
    if (verbose >= (level))                   \
        dr_fprintf(STDERR, fmt, __VA_ARGS__); \
} while (0)

#define OPTION_MAX_LENGTH MAXIMUM_PATH

#define COVERAGE_BB 0
#define COVERAGE_EDGE 1

typedef struct _target_module_t {
	char module_name[MAXIMUM_PATH];
	void *next;
} target_module_t;

typedef struct _winafl_option_t {
	/* Use nudge to notify the process for termination so that
	* event_exit will be called.
	*/
	BOOL nudge_kills;
	BOOL debug_mode;
	int coverage_kind;
	char logdir[MAXIMUM_PATH];
	target_module_t *target_modules;
	//char instrument_module[MAXIMUM_PATH];
	char fuzz_module[MAXIMUM_PATH];
	char fuzz_method[MAXIMUM_PATH];
	char pipe_name[MAXIMUM_PATH];
	char shm_name[MAXIMUM_PATH];
	unsigned long fuzz_offset;
	int fuzz_iterations;
	void **func_args;
	int num_fuz_args;
} winafl_option_t;
static winafl_option_t options;

#define NUM_THREAD_MODULE_CACHE 4

#define NUM_GLOBAL_MODULE_CACHE 8
typedef struct _drvector_t {
	uint entries;   /**< The index at which drvector_append() will write. */
	uint capacity;  /**< The size of \p array. */
	void **array;   /**< The dynamically allocated storage for the vector entries. */
	bool synch;     /**< Whether to automatically synchronize each operation. */
	void *lock;     /**< The lock used for synchronization. */
	void(*free_data_func)(void*);  /**< The routine called when freeing each entry. */
} drvector_t;

typedef struct _module_entry_t {
	int  id;
	BOOL unload; /* if the module is unloaded */
	module_data_t *data;
} module_entry_t;

typedef struct _module_table_t {
	drvector_t vector;
	/* for quick query without lock, assuming pointer-aligned */
	module_entry_t *cache[NUM_GLOBAL_MODULE_CACHE];
} module_table_t;
typedef struct _winafl_data_t {
	module_entry_t *cache[NUM_THREAD_MODULE_CACHE];
	file_t  log;
	//unsigned char afl_area[MAP_SIZE];
	unsigned char *afl_area;

#ifdef _WIN64
	uint64 previous_offset;
#else
	unsigned int previous_offset;
#endif

} winafl_data_t;
static winafl_data_t winafl_data;

typedef struct _fuzz_target_t {
	ULONG64 xsp;            /* stack level at entry to the fuzz target */
	app_pc func_pc;
	CONTEXT CpuState;
	char testcase_filename[MAXIMUM_PATH];
	wchar_t testcase_filename_w[MAXIMUM_PATH];
	int iteration;
} fuzz_target_t;
static fuzz_target_t fuzz_target;

static module_table_t *module_table;
//static client_id_t client_id;

static volatile BOOL go_native;

static void
event_exit(void);

static HANDLE pipe;

/****************************************************************************
* Nudges
*/

enum {
	NUDGE_TERMINATE_PROCESS = 1,
};
