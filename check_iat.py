#!/usr/bin/env python3
"""
check_iat.py - Verify no suspicious Windows APIs appear in a PE's Import
Address Table (IAT).

All security-sensitive APIs in this project are resolved at runtime through
PEB-walk + DJB2 API-hashing.  The IAT must only contain benign decoy entries.
This script parses the import table via objdump and fails if any known-bad
function name is found.

Usage:
    python3 check_iat.py [--objdump CMD] binary [binary ...]

Exit codes:
    0 - Clean
    1 - Suspicious import(s) detected
    2 - Tool error (objdump not found, etc.)
"""

import argparse
import re
import subprocess
import sys

# ---------------------------------------------------------------------------
# Blocklist - regex patterns matched against every imported function name.
# Grouped by threat category.  Any match -> hard failure.
# ---------------------------------------------------------------------------
FORBIDDEN = [
    # -- Token / Privilege / Impersonation --
    r"OpenProcessToken",
    r"OpenThreadToken",
    r"DuplicateToken",                    # catches DuplicateTokenEx
    r"AdjustTokenPrivilege",              # catches AdjustTokenPrivileges
    r"LookupPrivilegeValue",
    r"SetThreadToken",
    r"ImpersonateLoggedOnUser",
    r"RevertToSelf",
    r"GetTokenInformation",
    r"SetTokenInformation",
    r"NtOpenProcessToken",
    r"NtAdjustPrivilegesToken",
    # -- LSA / Kerberos --
    r"LsaConnectUntrusted",
    r"LsaLookupAuthenticationPackage",
    r"LsaCallAuthenticationPackage",
    r"LsaFreeReturnBuffer",
    r"LsaDeregisterLogonProcess",
    # -- SSPI --
    r"AcquireCredentialsHandle",
    r"InitializeSecurityContext",
    r"DeleteSecurityContext",
    r"FreeCredentialsHandle",
    r"FreeContextBuffer",
    r"QueryContextAttributes",
    r"QuerySecurityPackageInfo",
    # -- WTS / Session --
    r"WTSQueryUserToken",
    r"WTSEnumerateSessions",
    r"WTSQuerySessionInformation",
    r"WTSFreeMemory",
    # -- Process creation with token --
    r"CreateProcessAsUser",
    r"CreateProcessWithToken",
    r"^CreateProcess[AW]$",
    # -- Process enumeration (Toolhelp) --
    r"CreateToolhelp32Snapshot",
    r"Process32First",
    r"Process32Next",
    # -- Security Descriptors / ACL --
    r"SecurityDescriptor",                # catches Initialize*, Set*, Get*
    r"InitializeAcl",
    r"AddAccessAllowedAce",
    r"^AddAce$",
    r"^GetAce$",
    r"GetAclInformation",
    r"KernelObjectSecurity",              # catches Get*/Set*
    r"ConvertStringSecurityDescriptor",
    # -- SID --
    r"AllocateAndInitializeSid",
    r"LookupAccountSid",
    r"^FreeSid$",
    r"^GetLengthSid$",
    # -- COM / OLE --
    r"CoRegisterClassObject",
    r"CoRevokeClassObject",
    r"CoInitializeSecurity",
    r"CoInitializeEx",
    r"CoCreateInstance",
    r"CoUninitialize",
    r"CoCreateGuid",
    r"CLSIDFromString",
    r"CLSIDFromProgID",
    r"CreateBindCtx",
    r"MkParseDisplayName",
    r"VariantInit",
    r"VariantClear",
    r"SysAllocString",
    r"SysFreeString",
    # -- Registry mutation (reads are OK - they are decoys) --
    r"RegCreateKeyEx",
    r"RegSetValueEx",
    r"RegDeleteKey",
    # -- NT native --
    r"NtOpenKeyEx",
    r"NtEnumerateKey",
    r"NtEnumerateValueKey",
    r"^NtClose$",
    # -- Network / AD --
    r"NetUserAdd",
    r"NetGroupAdd",
    r"DsGetDcName",
    r"NetApiBufferFree",
    # -- Crypto --
    r"CryptStringToBinary",
    # -- Named pipes --
    r"CreateNamedPipe",
    r"ConnectNamedPipe",
    r"DisconnectNamedPipe",
    r"ImpersonateNamedPipeClient",
    # -- Dynamic loading (must use PEB walk) --
    r"^LoadLibrary[AW]$",
    r"^GetProcAddress$",
    # -- Environment block --
    r"CreateEnvironmentBlock",
    r"DestroyEnvironmentBlock",
]

# ---------------------------------------------------------------------------
# Extended blocklist - suspicious APIs NOT currently used in our binaries,
# but commonly flagged by EDR/AV.  Catches future regressions if a new
# feature accidentally pulls in a hot API via static import.
# ---------------------------------------------------------------------------
FORBIDDEN_EXTRA = [
    # -- Memory injection / shellcode --
    r"VirtualAllocEx",
    r"VirtualAlloc(?!Ex)",                # VirtualAlloc (local) is also flagged
    r"VirtualProtectEx",
    r"WriteProcessMemory",
    r"ReadProcessMemory",
    r"NtAllocateVirtualMemory",
    r"NtProtectVirtualMemory",
    r"NtWriteVirtualMemory",
    r"NtReadVirtualMemory",
    r"NtMapViewOfSection",
    r"NtUnmapViewOfSection",
    r"NtCreateSection",
    # -- Thread injection / execution --
    r"CreateRemoteThread",
    r"NtCreateThreadEx",
    r"RtlCreateUserThread",
    r"QueueUserAPC",
    r"NtQueueApcThread",
    r"SetWindowsHookEx",
    r"NtSetContextThread",
    r"ResumeThread",                      # suspicious when combined with CREATE_SUSPENDED
    # -- Process hollowing / ghosting --
    r"NtUnmapViewOfSection",
    r"NtResumeProcess",
    r"NtSuspendProcess",
    r"UpdateProcThreadAttribute",         # PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    r"InitializeProcThreadAttributeList",
    # -- Credential access --
    r"LsaRegisterLogonProcess",
    r"LsaEnumerateLogonSessions",
    r"LsaGetLogonSessionData",
    r"CredEnumerate",
    r"CredRead[AW]?$",
    r"SamConnect",
    r"SamOpenDomain",
    r"SamOpenUser",
    r"SamQueryInformationUser",
    r"MiniDumpWriteDump",
    r"^DbgHelp",                          # dbghelp.dll functions (minidump)
    # -- Registry hive direct access --
    r"RegSaveKey",
    r"RegLoadKey",
    r"RegRestoreKey",
    r"NtQueryKey",                        # EDR-hooked for boot key extraction
    # -- Service manipulation --
    r"CreateService[AW]",
    r"OpenService[AW]",
    r"StartService",
    r"ControlService",
    r"ChangeServiceConfig",
    r"OpenSCManager",
    # -- WMI execution --
    r"IWbemLocator",
    r"IWbemServices",
    # -- Anti-debug / anti-analysis --
    r"IsDebuggerPresent",
    r"CheckRemoteDebuggerPresent",
    r"NtQueryInformationProcess",
    r"NtSetInformationThread",            # ThreadHideFromDebugger
    # -- ETW tampering --
    r"EtwEventWrite",
    r"NtTraceEvent",
    r"EtwEventRegister",
    # -- AMSI bypass --
    r"AmsiInitialize",
    r"AmsiScanBuffer",
    r"AmsiOpenSession",
    # -- Dangerous process APIs --
    r"TerminateProcess",
    r"TerminateThread",
    r"NtTerminateProcess",
    # -- Token creation --
    r"NtCreateToken",
    r"ZwCreateToken",
    r"LogonUser[AW]",
    # -- Syscall / ntdll unhooking --
    r"NtSystemDebugControl",
    r"NtLoadDriver",
    r"NtUnloadDriver",
    # -- Keylogging / input capture --
    r"GetAsyncKeyState",
    r"GetKeyState",
    r"SetWindowsHookEx",
    r"GetRawInputData",
    # -- Screen / clipboard capture --
    r"BitBlt",
    r"GetDC",
    r"GetClipboardData",
    r"OpenClipboard",
    # -- Network / download --
    r"URLDownloadToFile",
    r"InternetOpen[AW]",
    r"InternetConnect[AW]",
    r"HttpOpenRequest[AW]",
    r"HttpSendRequest[AW]",
    r"InternetReadFile",
    # -- Dangerous NT native --
    r"NtCreateProcess",
    r"NtCreateUserProcess",
    r"RtlAdjustPrivilege",
]

_RE = [re.compile(p) for p in FORBIDDEN + FORBIDDEN_EXTRA]


# ---------------------------------------------------------------------------
# PE import-table extraction via objdump
# ---------------------------------------------------------------------------
def extract_imports(pe_path: str, objdump: str) -> list:
    """Return [(dll, func), ...] from the PE import table."""
    try:
        raw = subprocess.check_output(
            [objdump, "-p", pe_path], stderr=subprocess.STDOUT, text=True
        )
    except FileNotFoundError:
        print(f"[!] objdump not found: {objdump}", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as exc:
        print(f"[!] objdump failed on {pe_path}: {exc}", file=sys.stderr)
        sys.exit(2)

    imports = []
    dll = None
    for line in raw.splitlines():
        dm = re.match(r"\s*DLL Name:\s*(\S+)", line)
        if dm:
            dll = dm.group(1)
            continue
        if dll:
            fm = re.match(r"\s+[0-9a-fA-F]+\s+\d+\s+(\S+)", line)
            if fm:
                imports.append((dll, fm.group(1)))
            elif not line.strip():
                dll = None
    return imports


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="PE IAT suspicious-API checker")
    ap.add_argument(
        "--objdump",
        default="x86_64-w64-mingw32-objdump",
        help="objdump binary (default: x86_64-w64-mingw32-objdump)",
    )
    ap.add_argument("binaries", nargs="+", metavar="BINARY")
    args = ap.parse_args()

    overall = True
    for pe in args.binaries:
        imports = extract_imports(pe, args.objdump)

        # Check each import against the blocklist
        results = []  # [(dll, func, matched_pattern | None)]
        for dll, func in imports:
            matched = None
            for rx in _RE:
                if rx.search(func):
                    matched = rx.pattern
                    break
            results.append((dll, func, matched))

        hits = [(d, f, p) for d, f, p in results if p is not None]

        print(f"\n{'=' * 64}")
        print(f"  {pe}  ({len(imports)} IAT entries)")
        print(f"{'=' * 64}")
        for dll, func, pat in results:
            tag = f"  << BLOCKED ({pat})" if pat else ""
            print(f"    {dll:30s} {func}{tag}")

        if hits:
            overall = False
            print(f"\n  [FAIL] {len(hits)} forbidden import(s) detected")
        else:
            print(f"\n  [PASS] IAT is clean")

    print()
    if overall:
        print("[+] ALL BINARIES PASSED - no suspicious APIs in IAT")
    else:
        print("[!] FAILED - suspicious APIs detected in IAT (see above)")
    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
