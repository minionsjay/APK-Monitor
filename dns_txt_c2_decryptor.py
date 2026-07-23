#!/usr/bin/env python3
"""
DNS-over-TXT C2 解密工具
用于分析使用 DNS TXT 记录分发 C2 配置的 Android 恶意软件

支持该家族的所有变体：
- 标准版（k 字段）：DF165C93, 187719, 184618 等
- 升级版（QNGAMEKEY + DoH/DoT）：183651 等

依赖: pip install pycryptodome xxtea-py

用法:
  python3 dns_txt_c2_decryptor.py <apk_path>
  python3 dns_txt_c2_decryptor.py <apk_path> --query-dns  # 实际查询 DNS TXT
"""

import base64
import hashlib
import json
import os
import re
import socket
import struct
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    HAS_AES = True
except ImportError:
    HAS_AES = False
    print("Warning: pycryptodome not installed. Install with: pip install pycryptodome")

try:
    import xxtea
    HAS_XXTEA = True
except ImportError:
    HAS_XXTEA = False
    print("Warning: xxtea-py not installed. Install with: pip install xxtea-py")


# ========== Constants (shared across all variants) ==========

STRINGFOG_KEY = "kWYoedTLztHL7dHrsLy99mVu5SHKBgJF"
SEED_S1 = base64.b64decode("eW5HM1JzUDlXcnQ0").decode()  # "ynG3RsP9Wrt4"
SEED_S2 = base64.b64decode("Nm1LZjJYaDhRdjdM").decode()  # "6mKf2Xh8Qv7L"
SEED_S3 = base64.b64decode("VGw1QnoxQzZOcDNK").decode()  # "Tl5Bz1C6Np3J"

# Derived keys
_SHA256_DIGEST = hashlib.sha256((SEED_S1 + SEED_S2 + SEED_S3).encode()).digest()
AES_KEY32 = base64.b64encode(_SHA256_DIGEST).decode()[:32]  # "Na0PzT8Aj44aIGXqWlyWcKQ10R67UnjV"
XXTEA_KEY16 = AES_KEY32[:16].encode()  # b"Na0PzT8Aj44aIGXq"

# APM6989 decrypted result (the AES key for decrypting NetworkConstant.k)
K_AES_KEY = "qRXdx78YqrwMZSz6sboSPgbAoREjIeZa"

# APM6990[i] decrypted results (the AES keys for decrypting DNS TXT records)
TXT_AES_KEYS = {
    0: "445XeO2RtBUJgZMPku7SOwzGwAqiAlAZ",
    1: "RKwifmZxHVaECYF0rxwuEZTLDy7ofjAY",
    2: "50mUJ3qy9eOk3WH5xgUPUUdduwiv7yGv",
}

# The common suffix of APM6989/6990 encrypted array elements
ARRAY_SUFFIX = "2Cy4ZD2EcSlc6OA0uHXE="


# ========== Decryption functions ==========

def stringfog_decrypt(cipher: str) -> Optional[str]:
    """StringFog XOR decryption (layer 1)."""
    try:
        raw = base64.urlsafe_b64decode(cipher + "=" * (-len(cipher) % 4))
    except Exception:
        try:
            raw = base64.b64decode(cipher + "=" * (-len(cipher) % 4))
        except Exception:
            return None
    out = bytearray(raw)
    for i in range(len(out)):
        out[i] ^= ord(STRINGFOG_KEY[i % len(STRINGFOG_KEY)])
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return out.decode("utf-8", errors="replace")


def aes_ecb_decrypt(ciphertext: bytes, key_str: str) -> bytes:
    """AES-256-ECB-PKCS5Padding decryption (layer 2)."""
    cipher = AES.new(key_str.encode("utf-8")[:32], AES.MODE_ECB)
    pt = cipher.decrypt(ciphertext)
    try:
        pt = unpad(pt, 16)
    except Exception:
        pass
    return pt


def xxtea_decrypt_bytes(data: bytes, key16: bytes) -> bytes:
    """XXTEA decryption (layer 4)."""
    return xxtea.decrypt(data, key16)


def decrypt_array_element(cipher: str) -> Optional[str]:
    """Full decryption of a single APM6989/6990 array element.
    
    Chain: StringFog XOR → AES-256-ECB → Base64.decode → XXTEA
    Returns: 8-character base64 fragment string
    """
    inner = stringfog_decrypt(cipher)
    if inner is None:
        return None
    ct1 = base64.b64decode(inner)
    aes_pt = aes_ecb_decrypt(ct1, AES_KEY32)
    pt_str = aes_pt.decode("utf-8", errors="replace")
    ct2 = base64.b64decode(pt_str + "=" * (-len(pt_str) % 4))
    plain = xxtea_decrypt_bytes(ct2, XXTEA_KEY16)
    return plain.decode("utf-8", errors="replace")


def decrypt_network_constant_k(k_value: str) -> Optional[dict]:
    """Decrypt NetworkConstant.k (or QNGAMEKEY).
    
    Chain: Base64.decode (outer) → AES-256-ECB with K_AES_KEY
    Returns: dict with 'config_text', 'dns_groups', 'c2_ports', etc.
    """
    # Step 1: outer base64 decode
    step1 = base64.b64decode(k_value).decode("utf-8")
    # Step 2: AES-ECB decrypt
    ct = base64.b64decode(step1)
    cipher = AES.new(K_AES_KEY.encode("utf-8"), AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except Exception:
        pass
    text = pt.decode("utf-8", errors="replace")
    
    if "|" not in text:
        return None
    
    parts = text.split("|")
    dns_groups = []
    for idx, part in enumerate(parts):
        part = part.strip()
        if "," in part and "." in part:
            # Format: domain,dns_server1,dns_server2
            dns_groups.append({
                "field_index": idx,
                "config": part,
                "domain": part.split(",")[0] if "," in part else "",
                "dns_servers": [s.strip() for s in part.split(",")[1:]] if "," in part else [],
            })
    
    # Extract C2 ports (fields 6-9)
    c2_ports = []
    for idx in range(6, min(10, len(parts))):
        try:
            c2_ports.append(int(parts[idx].strip()))
        except (ValueError, IndexError):
            pass
    
    return {
        "config_text": text,
        "parts": parts,
        "dns_groups": dns_groups,
        "c2_ports": c2_ports,
        "token_field0": parts[0] if len(parts) > 0 else "",
        "token_field2": parts[2] if len(parts) > 2 else "",
    }


def decrypt_txt_record(txt_b64: str, dns_group: int) -> Optional[dict]:
    """Decrypt a DNS TXT record.
    
    Uses TXT_AES_KEYS[dns_group] as AES-256-ECB key.
    Returns: dict with 'text', 'c2_endpoints', 'token'
    """
    key = TXT_AES_KEYS.get(dns_group)
    if key is None:
        return None
    
    ct = base64.b64decode(txt_b64)
    cipher = AES.new(key.encode("utf-8"), AES.MODE_ECB)
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except Exception:
        pass
    text = pt.decode("utf-8", errors="replace")
    
    c2_endpoints = []
    token = ""
    for part in text.split("|"):
        part = part.strip()
        if not part:
            continue
        if part.startswith("@"):
            token = part
            continue
        try:
            ip_int, port = part.split(",")
            ip_int = int(ip_int)
            port = int(port)
            if ip_int > 4294967295:
                ip_int = ip_int % (2**32)
            ip_str = socket.inet_ntoa(struct.pack("!I", ip_int))
            c2_endpoints.append({"ip": ip_str, "port": port})
        except (ValueError, IndexError):
            pass
    
    return {
        "text": text,
        "c2_endpoints": c2_endpoints,
        "token": token,
    }


# ========== APK extraction functions ==========

def find_b64_strings(data: bytes, min_len: int = 60) -> List[str]:
    """Find long base64 strings in binary data."""
    results = []
    i = 0
    while i < len(data):
        if (0x41 <= data[i] <= 0x5A or 0x61 <= data[i] <= 0x7A or
            0x30 <= data[i] <= 0x39 or data[i] in (0x2B, 0x2F, 0x3D)):
            start = i
            while i < len(data) and (0x41 <= data[i] <= 0x5A or 0x61 <= data[i] <= 0x7A or
                   0x30 <= data[i] <= 0x39 or data[i] in (0x2B, 0x2F, 0x3D)):
                i += 1
            run = data[start:i]
            if len(run) >= min_len:
                results.append(run.decode("ascii"))
        else:
            i += 1
    return results


def extract_k_from_apk(apk_path: str) -> Optional[dict]:
    """Extract NetworkConstant.k (or QNGAMEKEY) from an APK.
    
    Searches all .dex files for long base64 strings that decode to
    another valid base64 string (double-base64 pattern).
    """
    with zipfile.ZipFile(apk_path) as zf:
        for dex_name in sorted([n for n in zf.namelist() if n.endswith(".dex")]):
            try:
                dex_data = zf.read(dex_name)
            except RuntimeError:
                continue
            if b"NetworkConstant" not in dex_data and b"APM6986" not in dex_data:
                continue
            
            b64_strings = find_b64_strings(dex_data, min_len=200)
            for s in b64_strings:
                try:
                    decoded = base64.b64decode(s + "=" * (-len(s) % 4))
                    if len(decoded) > 500 and all(b < 128 for b in decoded):
                        inner_str = decoded.decode("ascii", errors="replace")
                        if re.match(r'^[A-Za-z0-9+/=]+$', inner_str):
                            return {
                                "k_value": s,
                                "dex_file": dex_name,
                                "k_length": len(s),
                                "inner_length": len(inner_str),
                            }
                except Exception:
                    pass
    return None


def check_apk_family(apk_path: str) -> dict:
    """Check if an APK belongs to this malware family."""
    indicators = [
        b"NetworkConstant", b"AppProtectManager", b"stringfog",
        b"StringFogImpl", b"APM6986", b"APM6990",
        b"org/xbill/DNS", b"xbill/DNS",
        b"OSS_URL", b"BW-755-", b"kWYoedTL",
        b"sdfkjn755fvb", b"d1s2a7ug5kds5baa",
        b"51island", b"68pulse", b"7docn", b"ddocarchive",
        b"ddocnote", b"ddocsearch", b"ddocmark",
        b"cn.bw755", b"cn.bw677",
    ]
    
    found = []
    try:
        with zipfile.ZipFile(apk_path) as zf:
            dex_files = [n for n in zf.namelist() if n.endswith(".dex")]
            for dex_name in dex_files:
                try:
                    dex_data = zf.read(dex_name)
                except RuntimeError:
                    # Encrypted dex, skip
                    continue
                for ind in indicators:
                    if ind in dex_data and ind.decode() not in found:
                        found.append(ind.decode())
    except Exception:
        pass
    
    return {
        "is_family": len(found) >= 2,
        "indicators": found,
        "indicator_count": len(found),
    }


# ========== DNS query function ==========

def query_txt_record(domain: str, dns_server: str) -> Optional[str]:
    """Query DNS TXT record using dig command."""
    import subprocess
    try:
        result = subprocess.run(
            ["dig", "+short", f"@{dns_server}", "TXT", domain],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        # dig wraps TXT in quotes: "base64data"
        if output.startswith('"'):
            return output.strip('"').strip()
        return output if output else None
    except Exception as e:
        return None


# ========== Main analysis function ==========

def analyze_apk(apk_path: str, query_dns: bool = False) -> dict:
    """Full analysis of a single APK.
    
    Args:
        apk_path: Path to the APK file
        query_dns: If True, actually query DNS TXT records
    
    Returns: dict with all analysis results
    """
    result = {
        "apk_path": apk_path,
        "apk_name": os.path.basename(apk_path),
        "apk_size": os.path.getsize(apk_path),
    }
    
    # Check family
    family_check = check_apk_family(apk_path)
    result["is_family"] = family_check["is_family"]
    result["indicators"] = family_check["indicators"]
    
    if not family_check["is_family"]:
        return result
    
    # Extract k value
    k_info = extract_k_from_apk(apk_path)
    if not k_info:
        result["error"] = "k value not found"
        return result
    
    result["k_info"] = k_info
    
    # Decrypt k
    k_decrypted = decrypt_network_constant_k(k_info["k_value"])
    if not k_decrypted:
        result["error"] = "k decryption failed"
        return result
    
    result["k_decrypted"] = k_decrypted
    
    # Query DNS TXT and decrypt C2
    if query_dns:
        all_c2 = []
        for dg in k_decrypted["dns_groups"]:
            domain = dg["domain"]
            dns_servers = dg["dns_servers"]
            for ns in dns_servers:
                txt = query_txt_record(domain, ns)
                if txt:
                    grp_idx = dg["field_index"] - 23  # dnsGroup 0/1/2
                    if 0 <= grp_idx <= 2:
                        c2_data = decrypt_txt_record(txt, grp_idx)
                        if c2_data:
                            for ep in c2_data["c2_endpoints"]:
                                ep["dns_group"] = grp_idx
                                ep["txt_domain"] = domain
                                all_c2.append(ep)
                    break  # only need one successful query
        result["c2_endpoints"] = all_c2
    
    return result


def batch_analyze(directory: str, query_dns: bool = False) -> List[dict]:
    """Analyze all APKs in a directory."""
    results = []
    apks = sorted([f for f in os.listdir(directory) if f.endswith(".apk")])
    
    for apk_name in apks:
        apk_path = os.path.join(directory, apk_name)
        r = analyze_apk(apk_path, query_dns=query_dns)
        results.append(r)
        
        status = "🔴" if r.get("is_family") else "⚪"
        c2_count = len(r.get("c2_endpoints", []))
        print(f"{status} {apk_name} ({r['apk_size']//1024//1024}MB) "
              f"indicators={len(r.get('indicators',[]))} "
              f"c2={c2_count}")
    
    return results


# ========== CLI ==========

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    if not HAS_AES or not HAS_XXTEA:
        print("Missing dependencies. Install: pip install pycryptodome xxtea-py")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    query_dns = "--query-dns" in sys.argv
    
    if os.path.isdir(apk_path):
        results = batch_analyze(apk_path, query_dns=query_dns)
        # Summary
        family = [r for r in results if r.get("is_family")]
        print(f"\n=== Summary ===")
        print(f"Total: {len(results)}, Family: {len(family)}")
        all_c2 = []
        for r in family:
            for ep in r.get("c2_endpoints", []):
                all_c2.append(ep)
        if all_c2:
            print(f"\nTotal C2 endpoints: {len(all_c2)}")
            unique_ips = sorted(set(ep["ip"] for ep in all_c2))
            print(f"Unique C2 IPs: {len(unique_ips)}")
            for ip in unique_ips:
                print(f"  {ip}")
    else:
        result = analyze_apk(apk_path, query_dns=query_dns)
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
