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
#include <wincrypt.h>
#include <winternl.h>
#include "lib.h"
#include "structs.h"
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

BYTE HexCharToByte(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return 0; // invalid input
}

bool HexStringToByteArray(const char* hexString, BYTE* byteArray, DWORD byteArrayLen) {
    size_t len = strlen(hexString);
    if (len % 2 != 0 || byteArrayLen < len / 2) {
        return false;
    }

    for (size_t i = 0; i < len / 2; ++i) {
        byteArray[i] = (HexCharToByte(hexString[2 * i]) << 4) | HexCharToByte(hexString[2 * i + 1]);
    }
    return true;
}

bool HashString(const char* data, BYTE* hash, DWORD& hashLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    // Acquire a cryptographic provider context handle
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        WriteConsole("CryptAcquireContext failed: \n");
        return false;
    }

    // Create a hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        WriteConsole("CryptCreateHash failed: \n");
        CryptReleaseContext(hProv, 0);
        return false;
    }

    // Compute the cryptographic hash of the data
    if (!CryptHashData(hHash, (BYTE*)data, strlen(data), 0)) {
        WriteConsole("CryptHashData failed: \n");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    // Retrieve the hash value
    if(!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        WriteConsole("CryptGetHashParam failed: \n");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    // Clean up
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return true;
}

bool CompareByteArrays(const BYTE* arr1, const BYTE* arr2, DWORD len) {
    for (DWORD i = 0; i < len; ++i) {
        if (arr1[i] != arr2[i]) {
            return false;
        }
    }
    return true;
}

void RealCode()
{
    HWND hwnd = NULL;
    EnumWindows(EnumWindowsProc, (LPARAM)&hwnd);

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

    
    size_t buffSize = 4096;
    char* i_user = NewCharArray(buffSize);
    char* i_pass = NewCharArray(buffSize);
    
    const char* user_login_hash = "22152bf604ed0ae4e799c3c6435b88e699374832a9aeb161d47fc6b60123daad";
    const char* pass_login_hash = "1b816939ff203c1f721f476a9f98862c4170f0420c87fc24a9ffcf39befcace7";

    DWORD hashLen = 32;
    BYTE user_login_hash_bytes[32]; // SHA-256 produces a 32-byte hash
    BYTE pass_login_hash_bytes[32]; // SHA-256 produces a 32-byte hash

    HexStringToByteArray(user_login_hash, user_login_hash_bytes, hashLen);
    HexStringToByteArray(pass_login_hash, pass_login_hash_bytes, hashLen);

    BYTE user_hash_bytes[32];
    BYTE pass_hash_bytes[32];

    while (TRUE) {
        WriteConsole("User: ");
        ReadConsole(i_user, buffSize);
        WriteConsole("Pass: ");
        ReadConsole(i_pass, buffSize);
        HashString(i_user, user_hash_bytes, hashLen);
        HashString(i_pass, pass_hash_bytes, hashLen);
        if (CompareByteArrays(user_hash_bytes, user_login_hash_bytes, hashLen) && CompareByteArrays(pass_hash_bytes, pass_login_hash_bytes, hashLen))
        {
            WriteConsole("Congratulations u now are gay!");
            ExitProcess(0);
        }
        WriteConsole("Wrong!\n");
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

DWORD WINAPI TCDB(LPVOID qwNativeElapsed)
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
    if ((uiEnd.QuadPart - uiStart.QuadPart) <= 0)
    {
        RealCode();
    }

    return (uiEnd.QuadPart - uiStart.QuadPart) > 0;
}

extern "C" void WinMainCRTStartup()
{
    HANDLE hThread;
    DWORD threadId;
    PVOID param = NULL;
    hThread = CreateThread(
        NULL,                   // Default security attributes
        0,                      // Default stack size (0 uses the default size)
        TCDB,         // Thread function to execute
        param,                 // Pointer to the parameter to pass to the thread
        0,                      // Creation flags (0 for normal execution)
        &threadId               // Pointer to variable to receive the thread ID
    );

    while (1)
    {
        Sleep(5);
    }
    CloseHandle(hThread);
    // if (TCDB(0))
    // {   
    //     ExitProcess(EXIT_FAILURE);
    // }
    ExitProcess(EXIT_SUCCESS);
}