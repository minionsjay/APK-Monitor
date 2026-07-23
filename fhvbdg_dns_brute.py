import subprocess, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

AES_KEY = b"gYCtoT08cKxQjwVh4m2iyUfEI19WG3Yz"
BASE = "hycuigda052.gnzsmn.com"

def decrypt_txt(txt):
    try:
        ct = base64.b64decode(txt)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_KEY[:16])
        pt = unpad(cipher.decrypt(ct), 16)
        return pt.decode()
    except:
        return None

prefixes = [
    "sdkcgyuf052", "sdkcgyuf152", "sdkcgyuf252", "sdkcgyuf352",
    "node1", "node2", "node3", "node4", "node5", "node6", "node7", "node8",
    "api", "proxy", "sdk", "control", "cgyuf052",
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
    "grp0", "grp1", "grp2", "grp3",
    "line1", "line2", "line3",
    "fwd1", "fwd2", "fwd3",
    "p1", "p2", "p3", "p4", "p5",
    "s1", "s2", "s3", "s4", "s5",
    "v1", "v2", "v3",
]

found_ips = set()
found_ips.add("43.248.2.74")

for prefix in prefixes:
    domain = prefix + "." + BASE
    try:
        result = subprocess.run(
            ["dig", "+short", "+time=3", "@8.8.8.8", "TXT", domain],
            capture_output=True, text=True, timeout=5
        )
        records = [l.strip().strip('"') for l in result.stdout.splitlines() if l.strip()]
        for rec in records:
            ip = decrypt_txt(rec)
            if ip and ip[0].isdigit():
                found_ips.add(ip)
                print(f"OK {domain} -> {ip}")
    except:
        pass

print(f"\n=== Found {len(found_ips)} nodes ===")
for ip in sorted(found_ips):
    print(f"  {ip}:30052")
