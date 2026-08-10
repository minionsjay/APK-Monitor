# Pipeline Integration Notes for Redroid

## ADB Connection

From WSL, use Windows adb.exe through SSH tunnel:

```
# SSH tunnel (background)
python3 /tmp/tunnel.py  # forks ssh -L 5555:127.0.0.1:5555 -N ubuntu@SERVER

# Connect
ADB=/mnt/c/Users/minions/AppData/Local/Android/Sdk/platform-tools/adb.exe
$ADB connect 127.0.0.1:5555
```

## APK Installation (10 seconds)

```python
# Use Windows path for adb.exe (it's a Windows binary)
win_apk_path = apk_path.replace('/mnt/e/', 'E:\\').replace('/mnt/c/', 'C:\\').replace('/', '\\')
subprocess.run([ADB, '-s', '127.0.0.1:5555', 'install', '-r', win_apk_path], timeout=120)
```

## Finding Launch Activity

Hardened APKs (加固壳) have obfuscated Activity names. `monkey -c LAUNCHER` returns exit -5.
Use `dumpsys package` to find the real LaunchActivity:

```python
r = run_adb(['shell', f'dumpsys package {pkg} | grep LaunchActivity'], timeout=5)
# Parse: "ewqmy.dplrmene.xpoailnla/oeb.cappvnlj.ui.LaunchActivity"
# Then: am start -n pkg/Activity
```

## Getting sdk_forwarder_fixed.json (5-6 seconds)

No root needed — json is under /sdcard:

```python
r = run_adb(['shell', f'cat /sdcard/Android/data/{pkg}/files/sdk_forwarder_fixed.json 2>/dev/null'], timeout=5)
# JSON appears in ~5 seconds after app launch
```

## Artifact Collection

Same paths as cloud-phone:
- `sdk_forwarder_fixed.json` — 15 proxy node IPs (no port)
- `sdk_cache.json` — .dat download URL + encrypted payload
- `sdk_device_uuid.txt` — device UUID
- `.dat` file — decode from sdk_cache.json payload_b64

## Display / Screenshot

With `androidboot.redroid_gpu_mode=guest androidboot.redroid_width=1080 androidboot.redroid_height=1920` parameters, screenshots CAN produce content (57-58KB PNGs with 1080x1920 resolution). Without GPU mode=guest, screenshots are pure white/black (25KB).

For reliable screenshots, use cloud phone (多多云) which has real virtual display.

## IP Rate Limiting (CONFIRMED — Progressive Degradation)

**Updated 2026-08-04**: Redroid on Tencent Cloud IS rate-limited. Success drops from 52% → 26% as APK count increases.

| Environment | Exit IP | Forward success | Verdict |
|-------------|---------|-----------------|---------|
| 多多云 (LXC) | 14.18.243.75 | 100% (199/199) | ✅ Best |
| Redroid Tencent | 175.178.184.44 | 26% (22/84) | ❌ Progressive block |
| WiFi | 58.153.46.2 | 3.5% (10/280) | ❌ Severe |
| Clash TW proxy | Taiwan IP | 0% | ❌ Foreign rejected |

**Key finding**: Rate limiting is PROGRESSIVE — gets worse over time. Not a fixed threshold. After ~70+ APKs from same IP, success drops to ~26%.

**Recommendation**: Use 多多多云手机 for production (100% success, 413/662 confirmed). Redroid only for small batches (<10 APKs) or with IP rotation.

## test-keys vs release-keys

Redroid uses `userdebug/test-keys` (AOSP), 多多云 uses `user/release-keys` (real OEM firmware). Control plane may detect test-keys as non-genuine. Possible alternative cause of rate limiting alongside IP.

## Huawei EMUI Firmware (for system.img extraction)

- **Huawei Firm Finder**: https://professorjtj.github.io/ — catalogs EMUI firmware by model/region/version
- Search "MRD-AL00" + "9.1" yields versions 9.1.0.276-9.1.0.299 (C00/C01/C700 regions)
- Exact 9.1.1.67 NOT found in database
- Firmware is UPDATE.APP format (OTA flash, not Docker image)
- Extraction requires HiSuite-Proxy tool (Windows GUI, https://github.com/ProfessorJTJ/HISuite-Proxy)
- Huawei download API: `https://query.hicloud.com:443/sp_ard_common/v1/authorize.action` + `update.dbankcdn.com/TDS/data/files/`
- No public API for direct download — must use HiSuite-Proxy or HiSuite tool
- HiSuite-Proxy source (C# .NET): GitHub download works via proxy (21MB zip)
- Pre-compiled release: HiSuite_11.0.0.610_OVE.exe (50MB, Windows only)
- **Warning**: EMUI system.img targets Hisilicon Kirin chips — may not boot on non-Hisilicon ARM64 (Tencent Cloud uses Ampere/Graviton)

## Performance Numbers

| Stage | Redroid | Cloud Phone |
|-------|---------|-------------|
| Install | 10s | 230s |
| Get JSON | 6s | 12s |
| Total | 16s | 245s |
| 662 APKs | ~3h | ~44h |
| Screenshots | Limited (white without GPU mode) | Yes (real) |
| IP风控 | Progressive (26% after 84 APKs) | None (100%) |

## Common Issues

- **PermissionError in Python fallback**: Don't use `subprocess.run([''])` in except blocks. Use `class R: stdout=''; stderr=''; returncode=-1`.
- **Image truncated in HTML**: Screenshot PNG may be incomplete. Wrap in try/except and skip if PIL can't open.
- **SSH tunnel drops**: Add `-o ServerAliveInterval=30` to ssh command. When tunnel drops, all installs show "安装失败(0.0s)" (0-second = device not found).
- **Server reboot clears /tmp**: Kernel source and .ko lost. Always `cp *.ko ~/`. Crontab @reboot handles re-loading.
- **ashmem.ko crashes kernel**: Do NOT load ashmem_linux.ko. Causes immediate kernel panic. Redroid 10 works without it (uses memfd).
