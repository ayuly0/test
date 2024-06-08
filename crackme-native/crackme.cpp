#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#endif

#pragma warning (push)
    /* 4820: '<struct-name>' : 'n' bytes padding added after data member '<member-name>'*/
#pragma warning (disable : 4820)
#include <windows.h>
#include <stdlib.h>
#include <intrin.h>
#include <winternl.h>
#include "lib.h"
#pragma intrinsic(_ReturnAddress)
#pragma warning (pop)

typedef unsigned long u32;

/*--------------------------------------------------------------------------------------------------------------------*/
#define DYNAMIC_IMPORTED_FUNC(rval, func, ...)\
    typedef rval (WINAPI *tpfn_##func)(__VA_ARGS__); \
    static tpfn_##func pfn_##func = 0;

#define DYNAMIC_SYSTEM_LOAD(lib, func)\
    ( ( pfn_##func = (tpfn_##func)dynamic_system_func_load(lib, #func) ) != 0 )

#define CALL(func, ...)\
    pfn_##func(__VA_ARGS__)

/*--------------------------------------------------------------------------------------------------------------------*/
#ifdef __cplusplus
#   define INLINE __forceinline
#else
#   define INLINE __inline
#endif

/* To prevent MSVC warning 4820 when compiling for x64 */
#ifdef _WIN64
#   define EXPLICIT_PADDING(n, size) BYTE padding_##n[size]
#else
#   define EXPLICIT_PADDING(n, size)
#endif

/*--------------------------------------------------------------------------------------------------------------------*/
static INLINE FARPROC dynamic_system_func_load(const char * module, const char * func)
{
    HMODULE handle = GetModuleHandleA(module);

    if (handle == 0)
    {
        handle = LoadLibraryA(module);
    }

    if (handle != 0)
    {
        return GetProcAddress(handle, func);
    }
    return 0;
}
/*--------------------------------------------------------------------------------------------------------------------*/
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    _Field_size_(NumberOfModules) RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX
{
    USHORT NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG ImageChecksum;
    ULONG TimeDateStamp;
    PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX;
typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION
{
    PCHAR SymbolicBackTrace;
    ULONG TraceCount;
    USHORT Index;
    USHORT Depth;
    PVOID BackTrace[32];
} RTL_PROCESS_BACKTRACE_INFORMATION, *PRTL_PROCESS_BACKTRACE_INFORMATION;
typedef struct _RTL_PROCESS_BACKTRACES
{
    ULONG CommittedMemory;
    ULONG ReservedMemory;
    ULONG NumberOfBackTraceLookups;
    ULONG NumberOfBackTraces;
    _Field_size_(NumberOfBackTraces) RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[1];
} RTL_PROCESS_BACKTRACES, *PRTL_PROCESS_BACKTRACES;
typedef struct _RTL_PROCESS_LOCK_INFORMATION
{
    PVOID Address;
    USHORT Type;
    USHORT CreatorBackTraceIndex;
    HANDLE OwningThread;
    LONG LockCount;
    ULONG ContentionCount;
    ULONG EntryCount;
    LONG RecursionCount;
    ULONG NumberOfWaitingShared;
    ULONG NumberOfWaitingExclusive;
} RTL_PROCESS_LOCK_INFORMATION, *PRTL_PROCESS_LOCK_INFORMATION;
typedef struct _RTL_PROCESS_LOCKS
{
    ULONG NumberOfLocks;
    _Field_size_(NumberOfLocks) RTL_PROCESS_LOCK_INFORMATION Locks[1];
} RTL_PROCESS_LOCKS, *PRTL_PROCESS_LOCKS;
typedef struct _RTL_PROCESS_VERIFIER_OPTIONS
{
    ULONG SizeStruct;
    ULONG Option;
    UCHAR OptionData[1];
} RTL_PROCESS_VERIFIER_OPTIONS, *PRTL_PROCESS_VERIFIER_OPTIONS;
typedef struct _RTL_DEBUG_INFORMATION
{
    HANDLE SectionHandleClient;
    PVOID ViewBaseClient;
    PVOID ViewBaseTarget;
    ULONG_PTR ViewBaseDelta;
    HANDLE EventPairClient;
    HANDLE EventPairTarget;
    HANDLE TargetProcessId;
    HANDLE TargetThreadHandle;
    ULONG Flags;
    SIZE_T OffsetFree;
    SIZE_T CommitSize;
    SIZE_T ViewSize;
    union
    {
        PRTL_PROCESS_MODULES Modules;
        PRTL_PROCESS_MODULE_INFORMATION_EX ModulesEx;
    };
    PRTL_PROCESS_BACKTRACES BackTraces;
    PVOID Heaps;
    PRTL_PROCESS_LOCKS Locks;
    PVOID SpecificHeap;
    HANDLE TargetProcessHandle;
    PRTL_PROCESS_VERIFIER_OPTIONS VerifierOptions;
    PVOID ProcessHeap;
    HANDLE CriticalSectionHandle;
    HANDLE CriticalSectionOwnerThread;
    PVOID Reserved[4];
} RTL_DEBUG_INFORMATION, *PRTL_DEBUG_INFORMATION;
typedef struct _RTL_HEAP_TAG
{
    ULONG NumberOfAllocations;
    ULONG NumberOfFrees;
    SIZE_T BytesAllocated;
    USHORT TagIndex;
    USHORT CreatorBackTraceIndex;
    WCHAR TagName[24];
} RTL_HEAP_TAG, *PRTL_HEAP_TAG;
typedef struct _RTL_HEAP_ENTRY
{
    SIZE_T Size;
    USHORT Flags;
    USHORT AllocatorBackTraceIndex;
    union
    {
        struct
        {
            SIZE_T Settable;
            ULONG Tag;
        } s1;
        struct
        {
            SIZE_T CommittedSize;
            PVOID FirstBlock;
        } s2;
    } u;
} RTL_HEAP_ENTRY, *PRTL_HEAP_ENTRY;
typedef struct _RTL_HEAP_INFORMATION_V1
{
    PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[5];
    PRTL_HEAP_TAG Tags;
    PRTL_HEAP_ENTRY Entries;
} RTL_HEAP_INFORMATION_V1, *PRTL_HEAP_INFORMATION_V1;
typedef struct _RTL_PROCESS_HEAPS_V1
{
    ULONG NumberOfHeaps;
    _Field_size_(NumberOfHeaps) RTL_HEAP_INFORMATION_V1 Heaps[1];
} RTL_PROCESS_HEAPS_V1, *PRTL_PROCESS_HEAPS_V1;
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef enum DebugInfoClassMask
{
    PDI_MODULES     = 0x01,
    PDI_BACKTRACE   = 0x02,
    PDI_HEAPS       = 0x04,
    PDI_HEAP_TAGS   = 0x08,
    PDI_HEAP_BLOCKS = 0x10,
    PDI_LOCKS       = 0x20
} DebugInfoClassMask;

DYNAMIC_IMPORTED_FUNC(PRTL_DEBUG_INFORMATION, RtlCreateQueryDebugBuffer, u32, u32);
DYNAMIC_IMPORTED_FUNC(NTSTATUS, RtlDestroyQueryDebugBuffer, PRTL_DEBUG_INFORMATION);
DYNAMIC_IMPORTED_FUNC(NTSTATUS, RtlQueryProcessDebugInformation, u32, u32, PRTL_DEBUG_INFORMATION);
DYNAMIC_IMPORTED_FUNC(NTSTATUS, RtlQueryProcessHeapInformation, PRTL_DEBUG_INFORMATION);
DYNAMIC_IMPORTED_FUNC(BOOL, IsDebuggerPresent);
DYNAMIC_IMPORTED_FUNC(BOOL, CheckRemoteDebuggerPresent, HANDLE, PBOOL);
DYNAMIC_IMPORTED_FUNC(BOOL, NtQueryInformationProcess, HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    DWORD windowPID;
    GetWindowThreadProcessId(hwnd, &windowPID);

    if (windowPID == GetCurrentProcessId()) {
        *(HWND*)lParam = hwnd;
        return FALSE;  // Stop enumeration
    }
    return TRUE;  // Continue enumeration
}

void WriteConsole(const char* message) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD charsWritten;
    WriteConsoleA(hConsole, message, strlen(message), &charsWritten, NULL);
}

void ReadConsole(char* buffer, DWORD bufferSize) {
    HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
    DWORD charsRead;
    ReadConsoleA(hConsole, buffer, bufferSize, &charsRead, NULL);
    buffer[charsRead - 2] = '\0';
}

void RealCode()
{
	HWND hwnd = NULL;
    EnumWindows(EnumWindowsProc, (LPARAM)&hwnd);
    // AllocConsole();
    // AttachConsole(GetCurrentProcessId());

    HANDLE hConsoleOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hConsoleInput = GetStdHandle(STD_INPUT_HANDLE);


    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsoleOutput, &csbi);
    SMALL_RECT windowRect;
    windowRect.Left = (csbi.dwSize.X - 50) / 2;  // Center horizontally
    windowRect.Top = (csbi.dwSize.Y - 50) / 2;   // Center vertically
    windowRect.Right = windowRect.Left + 50 - 1; // 45 columns
    windowRect.Bottom = windowRect.Top + 50 - 1; // 45 rows

    SetConsoleTitle("Crack Me");
    SetConsoleWindowInfo(hConsoleOutput, TRUE, &windowRect);

    // MessageBox(0, 0, 0, MB_OK);

	char* i_user = NewCharArray(1024);
	char* i_pass = NewCharArray(1024);
	// int r_user, r_pass;

	while (TRUE) {
		WriteConsole("User: ");
		ReadConsole(i_user, sizeof i_user);
		WriteConsole("Pass: ");
		ReadConsole(i_pass, sizeof i_pass);

		WriteConsole("\n");
		WriteConsole(i_user);
		WriteConsole(" ");
		WriteConsole(i_pass);
		WriteConsole("\n");
	}
    FreeCharArray(i_user);
	FreeConsole();
}

void AntiDump()
{
    const auto peb = (PPEB)__readgsqword(0x60);
    const auto in_load_order_module_list = (PLIST_ENTRY)peb->Ldr->Reserved2[1];
    const auto table_entry = CONTAINING_RECORD(in_load_order_module_list, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
    const auto p_size_of_image = (PULONG)&table_entry->Reserved3[1];
    *p_size_of_image = (ULONG)((INT_PTR)table_entry->DllBase + 0x100000);
}

BOOL TCDB(DWORD64 qwNativeElapsed)
{
    AntiDump();
    // PVOID pRetAddress = _ReturnAddress();
    // if (*(PBYTE)pRetAddress != 0xCC) // int 3
    // {
    //     DWORD dwOldProtect;
    //     if (VirtualProtect(pRetAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
    //     {
    //         *(PBYTE)pRetAddress = 0x90; // nop
    //         VirtualProtect(pRetAddress, 1, dwOldProtect, &dwOldProtect);
    //     }
    // }

	SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetLocalTime(&stStart);
    
    u32 result = 1;

    result = result && DYNAMIC_SYSTEM_LOAD("ntdll.dll", RtlCreateQueryDebugBuffer);
    result = result && DYNAMIC_SYSTEM_LOAD("ntdll.dll", RtlDestroyQueryDebugBuffer);
    result = result && DYNAMIC_SYSTEM_LOAD("ntdll.dll", RtlQueryProcessDebugInformation);
    result = result && DYNAMIC_SYSTEM_LOAD("ntdll.dll", NtQueryInformationProcess);
    result = result && DYNAMIC_SYSTEM_LOAD("kernel32.dll", IsDebuggerPresent);
    result = result && DYNAMIC_SYSTEM_LOAD("kernel32.dll", CheckRemoteDebuggerPresent);

	DWORD dwProcessDebugPort, dwReturned, dwProcessDebugFlags;
	NTSTATUS status;

	if (CALL(IsDebuggerPresent))
	{
		ExitProcess(EXIT_FAILURE);
	}

	auto pDebugBuffer = CALL(RtlCreateQueryDebugBuffer, 0, 0);
	if (!SUCCEEDED(CALL(RtlQueryProcessDebugInformation, GetCurrentProcessId(), PDI_HEAPS, pDebugBuffer)))
	{
		ExitProcess(EXIT_FAILURE);
	}
	ULONG dwFlags = ((PRTL_PROCESS_HEAPS_V1)pDebugBuffer)->Heaps[0].Flags;

	HANDLE hProcessDebugObject;
	const DWORD ProcessDebugObjectHandle = 0x1e;
	status = CALL(NtQueryInformationProcess, GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugObjectHandle, &hProcessDebugObject, sizeof(HANDLE), &dwReturned);
	if (NT_SUCCESS(status) && (0 != hProcessDebugObject))
	{
		ExitProcess(EXIT_FAILURE);
	}

	const DWORD ProcessDebugFlags = 0x1f;
    status = CALL(NtQueryInformationProcess, GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugFlags, &dwProcessDebugFlags, sizeof(DWORD), &dwReturned);
	if (NT_SUCCESS(status) && (0 == dwProcessDebugFlags))
	{
		ExitProcess(EXIT_FAILURE);
	}

    status = CALL(NtQueryInformationProcess, GetCurrentProcess(), ProcessDebugPort, &dwProcessDebugPort, sizeof(DWORD), &dwReturned);
	if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort))
	{
		ExitProcess(EXIT_FAILURE);
	}

	BOOL bDebuggerPresent;
	if (TRUE == CALL(CheckRemoteDebuggerPresent, GetCurrentProcess(), &bDebuggerPresent) && TRUE == bDebuggerPresent)
	{
		ExitProcess(EXIT_FAILURE);
	}

    GetLocalTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return false;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return false;

    uiStart.LowPart  = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart  = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    if ((uiEnd.QuadPart - uiStart.QuadPart) <= qwNativeElapsed)
    {
        RealCode();
    }

    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}

extern "C" void WinMainCRTStartup()
{
	if (TCDB(0))
	{	
		ExitProcess(EXIT_FAILURE);
	}
	ExitProcess(EXIT_SUCCESS);
}