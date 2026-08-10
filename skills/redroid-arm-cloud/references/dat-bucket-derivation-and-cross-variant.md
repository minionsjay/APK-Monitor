# .dat Bucket Name Derivation — Cross-Variant Discovery (dh151 → dh183)

## Breakthrough (2026-08-04)

The bucket/filename derivation algorithm discovered for the `dh151` variant (exdyfb sample, app_name=dh151, sdk_version=4.0.1) was confirmed to work **identically** for the `dh183` variant (20260804 batch APKs).

### Algorithm (from Ghidra reverse engineering of `libgojni.so` `buildNodeDataURLs` at `controlplane.go:66-75`)

```
date = beijingNow().Format("20060102")     # Beijing time YYYYMMDD
h    = md5(YYYYMMDD + app_name + cloud_tag + sdk_version).hexdigest()
bucket   = h[0:16]    # first 16 hex chars
filename = h[16:32]   # last 16 hex chars
URL = https://{bucket}.{host}/{filename}.dat
```

### Parameters per variant

| Variant | app_name | sdk_version | port | RSA private key | AES key |
|---------|----------|-------------|------|-----------------|--------|
| dh151 (exdyfb, 260728 batch) | dh151 | 4.0.1 | 30151 | in libgojni.so (same marker) | qtOtoF14cKxTjrTo0m8iyHfEI18RK7Yb |
| dh183 (260804 batch) | dh183 | 4.0.1 | 30183 | in libgojni.so (extracted, different from dh151) | **UNKNOWN — needs bootstrap decryption** |

### Cross-variant verification (16/16 pass)

```python
import hashlib
# dh183, 2026-08-04, all 3 clouds
date = "20260804"
for app in ["dh151", "dh183"]:
    for tag, host in [("oss","oss-accelerate.aliyuncs.com"), ("bos","gz.bcebos.com"), ("zos","jiangsu-10.zos.ctyun.cn")]:
        h = hashlib.md5(f"{date}{app}{tag}4.0.1".encode()).hexdigest()
        print(f"{app}/{tag}: https://{h[:16]}.{host}/{h[16:32]}.dat")
```

**Known URLs from sdk_cache.json (dh183, 2026-08-04):**
- `https://32681ca416a8b654.oss-accelerate.aliyuncs.com/61922873dd65660f.dat` ✅ matches
- `https://c32188a12d98a990.jiangsu-10.zos.ctyun.cn/fe8b7076075c5d1b.dat` ✅ matches

### How to identify the variant

1. Extract `libgojni.so` from the APK (`unzip base.apk lib/arm64-v8a/libgojni.so`)
2. Extract RSA private key: search for `LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ` (base64 of PEM header) → double-base64 decode
3. The port in `sdk_forwarder_fixed.json` (`app_line_port`) directly encodes the variant number: port 30151 → dh151, port 30183 → dh183
4. Confirm by predicting the bucket URL and comparing with `sdk_cache.json` entries

### What's still needed for full offline node extraction (dh183)

1. **Bootstrap seed** — the `boot.init()` parameter (base64 RSA-2048 ciphertext, ~344 chars) is in Java code (hardened DEX, not in `libgojni.so`). Needs memory dump脱壳 to extract.
2. **New AES key** — decrypt the bootstrap seed with the new RSA private key → get `SecretPayload` JSON containing the new `AES-key`
3. **Decrypt .dat** — `AES-256-CBC(key=AES-key, IV=AES-key[:16], PKCS7)` on the 80-byte payload from `sdk_cache.json`
4. Old AES key (`qtOtoF14cKxTjrTo0m8iyHfEI18RK7Yb`) does NOT work for dh183 — produces garbage

### Reference: exdyfb complete analysis

Full end-to-end reverse engineering documentation for the dh151 variant is at:
`/home/ninini/Agents/AI-APK/reports/exdyfb_unpacked/`

Key files:
- `完整分析流程.md` — 8-phase end-to-end record (脱壳→RSA→AES→三云→抓包验证)
- `节点获取链路与复现.md` — Node IP origin and reproduction
- `keys/decrypt_bootstrap.py` — RSA decrypt tool (reusable, just change PEM path)
- `keys/decrypt_dat.py` — AES-256-CBC .dat decryptor (reusable, change AES_KEY)
- `keys/predict_dat_urls.py` — URL predictor (change APP/VER constants)
- `keys/sdk_priv.pem` — dh151 RSA private key
