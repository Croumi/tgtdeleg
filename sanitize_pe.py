#!/usr/bin/env python3
"""Sanitize PE headers to remove cross-compiler fingerprints.

Patches applied:
1. Zeros DOS stub (between 0x40 and PE offset) — compiler-specific patterns
2. Zeros MajorLinkerVersion/MinorLinkerVersion — identifies exact ld version
3. Zeros Debug Directory entry — residual debug references
"""
import struct
import sys


def sanitize_pe(path):
    with open(path, 'r+b') as f:
        data = bytearray(f.read())

        # Locate PE signature offset from e_lfanew at 0x3C
        pe_offset = struct.unpack_from('<I', data, 0x3C)[0]

        # 1. Zero DOS stub (0x40 to pe_offset)
        #    Keep MZ header (0x00-0x3F) intact, just wipe the stub message
        stub_size = pe_offset - 0x40
        for i in range(0x40, pe_offset):
            data[i] = 0
        print(f'  [+] DOS stub zeroed ({stub_size} bytes)')

        # 2. Zero linker version in Optional Header
        #    Layout: PE sig (4) + COFF header (20) + OptionalHeader
        opt_hdr = pe_offset + 4 + 20
        magic = struct.unpack_from('<H', data, opt_hdr)[0]

        old_major = data[opt_hdr + 2]
        old_minor = data[opt_hdr + 3]
        data[opt_hdr + 2] = 0
        data[opt_hdr + 3] = 0
        print(f'  [+] Linker version zeroed (was {old_major}.{old_minor})')

        # 3. Zero Debug Directory entry
        #    PE32+ (0x20B): data directories start at opt_hdr + 112
        #    PE32  (0x10B): data directories start at opt_hdr + 96
        #    Debug is directory index 6
        if magic == 0x20B:  # PE32+
            dd_base = opt_hdr + 112
        else:  # PE32
            dd_base = opt_hdr + 96

        debug_entry = dd_base + 6 * 8  # Each entry is 8 bytes (RVA + Size)
        debug_rva, debug_size = struct.unpack_from('<II', data, debug_entry)
        if debug_rva != 0 or debug_size != 0:
            struct.pack_into('<II', data, debug_entry, 0, 0)
            print(f'  [+] Debug directory zeroed (was RVA=0x{debug_rva:X}, Size=0x{debug_size:X})')
        else:
            print(f'  [*] Debug directory already clean')

        f.seek(0)
        f.write(data)
        print(f'  [+] Sanitized: {path}')


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        sanitize_pe(arg)
