---
name: redroid-arm-cloud
description: "Deploy Redroid (Android-in-Docker) on ARM64 cloud servers for APK automated testing. Covers binder_linux kernel module compilation, Docker setup on China networks, ADB via SSH tunnel, and pipeline integration."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [Redroid, Android, Docker, ARM64, ADB, CloudServer, APK]
---

# Redroid Android Container on ARM64 Cloud Server

Deploy a headless Android 10 container (Redroid) on an ARM64 cloud server for automated APK installation/testing. Eliminates IP-based rate limiting (个人宽带IP风控) and runs 15x faster than cloud-phone services (16s/APK vs 245s).

## When to use this skill

- User needs to run Android APKs on a remote server without a physical device
- APK testing is blocked by IP rate limiting on personal WiFi (控制面IP风控)
- Cloud-phone services (多多云) are too slow (4min/APK) or keep disconnecting
- User wants to batch-install and test hundreds of APKs automatically

## Prerequisites

- **ARM64 (aarch64) Ubuntu 22.04 server** — x86 won't work (APK Go .so libraries crash on translation layers like ndk_translation/houdini)
- **2+ cores, 4GB+ RAM, 20GB+ storage** — minimum for 1 container
- **sudo access** — needed for kernel module loading and Docker
- **China network** — Docker Hub requires registry mirrors

## Architecture overview

```
WSL (Windows)                          ARM64 Cloud Server
  adb.exe ──SSH tunnel:5555──→  Docker container (Redroid)
                                  Android 10 / ARM64 native
                                  binder_linux.ko (compiled from kernel source)
                                  APK → sdk_forwarder_fixed.json
```

Key insight: Redroid is NOT an emulator. It runs Android natively on ARM64 hardware inside a Docker container. APK .so libraries execute directly — no translation overhead, no SIGILL crashes.

## Step 1: Install Docker + China mirrors

```bash
sudo apt update && sudo apt install -y docker.io
# Write daemon.json with China registry mirrors (essential — Docker Hub is blocked)
python3 -c "
import json
with open('/tmp/daemon.json','w') as f:
    json.dump({'registry-mirrors':[
        'https://docker.mirrors.ustc.edu.cn',
        'https://hub-mirror.c.163.com',
        'https://docker.m.daocloud.io'
    ]}, f)
"
sudo cp /tmp/daemon.json /etc/docker/daemon.json
sudo systemctl restart docker
```

**Pitfall**: Don't use `echo '{"key":"val"}'` to write daemon.json — shell quoting mangles JSON. Always use python3's `json.dump`.

## Step 2: Compile binder_linux kernel module

Redroid requires the `binder` IPC kernel module. Stock Ubuntu 22.04 kernel (5.15) does NOT include it. Must compile from kernel source.

```bash
sudo apt install -y linux-source-5.15.0 flex bison libssl-dev libelf-dev bc build-essential
cd /tmp && tar xf /usr/src/linux-source-5.15.0.tar.bz2
cd /tmp/linux-source-5.15.0
cp /boot/config-$(uname -r) .config

# CRITICAL: Temporarily disable STACKPROTECTOR_PER_TASK to allow make modules_prepare
# (asm-offsets.h isn't generated yet, so -mstack-protector-guard-offset= has no value → build fails)
sed -i '/ifeq.*STACKPROTECTOR_PER_TASK/,/endif/s/^/#DISABLED# /' arch/arm64/Makefile
yes "" | make oldconfig
make modules_prepare   # generates include/generated/*, include/generated/asm-offsets.h
# RESTORE the disabled lines (asm-offsets.h now exists with TSK_STACK_CANARY value)
sed -i 's/#DISABLED# //' arch/arm64/Makefile

# Compile only the binder module (fast, ~30 seconds)
make M=drivers/android modules
# Copy .ko to persistent storage (survives reboot)
cp drivers/android/binder_linux.ko ~/
```

**Pitfall**: `ashmem_linux.ko` from `drivers/staging/android/` causes **kernel panic / server crash** on Ubuntu 22.04 ARM64. Do NOT load it. Redroid 10 works without it (uses memfd instead).

**Pitfall**: `make prepare` (full kernel prepare) takes 5+ minutes and times out. Use `make modules_prepare` instead — it's faster and generates the needed headers.

## Step 3: Load binder + start Redroid

```bash
sudo insmod ~/binder_linux.ko
sudo mkdir -p /dev/binderfs
sudo mount -t binder binder /dev/binderfs
# Verify
grep binder /proc/filesystems    # should show "nodev binder"
ls /dev/binderfs/                # should show binder-control, features

# Pull and start Redroid
sudo docker pull redroid/redroid:10.0.0-latest
sudo docker run -d --name redroid \
    --privileged \
    -p 5555:5555 \
    -v /dev/binderfs:/dev/binderfs \
    -v ~/redroid-data:/data \
    redroid/redroid:10.0.0-latest

# Wait 30s for Android to boot, then connect ADB
sleep 30
sudo apt install -y adb
adb connect 127.0.0.1:5555
adb devices    # should show 127.0.0.1:5555  device
```

**Pitfall**: Container exits with code 129 immediately if binderfs is not mounted. Always mount binderfs BEFORE starting the container.

## Step 4: Connect from WSL via SSH tunnel

Cloud server port 5555 is not exposed to the public internet (security group blocks it). Use SSH local port forwarding:

```python
# /tmp/tunnel.py — SSH tunnel: local:5555 → server:5555
import pty, os, time, socket
pid, fd = pty.fork()
if pid == 0:
    os.execvp('ssh', ['ssh', '-o', 'StrictHostKeyChecking=no',
                      '-o', 'ServerAliveInterval=30',
                      '-L', '5555:127.0.0.1:5555', '-N',
                      'ubuntu@SERVER_IP'])
else:
    time.sleep(5)
    os.write(fd, b'PASSWORD\n')
    time.sleep(5)
    # Keep alive
    while True: time.sleep(60)
```

Run in background, then connect with Windows adb.exe:
```bash
/mnt/c/Users/minions/AppData/Local/Android/Sdk/platform-tools/adb.exe connect 127.0.0.1:5555
```

## Step 5: APK installation pattern

```python
# Install (10 seconds on Redroid vs 230s on cloud-phone)
adb install -r 'C:\path\to\apk.apk'  # Windows path for adb.exe

# Find launch activity (monkey -c LAUNCHER sometimes fails on hardened APKs)
adb shell "dumpsys package <pkg> | grep LaunchActivity"
# → oeb.cappvnlj.ui.LaunchActivity

# Start with am start (not monkey — hardened APKs need direct Activity)
adb shell "am start -n <pkg>/<launch_activity>"

# Check for sdk_forwarder_fixed.json (appears in ~5 seconds!)
sleep 5
adb shell "cat /sdcard/Android/data/<pkg>/files/sdk_forwarder_fixed.json"
```

## Step 6: Auto-start on reboot

```bash
# /home/ubuntu/start_redroid.sh
#!/bin/bash
sleep 5
sudo insmod /home/ubuntu/binder_linux.ko 2>/dev/null
sudo mkdir -p /dev/binderfs
sudo mount -t binder binder /dev/binderfs 2>/dev/null
sudo docker start redroid 2>/dev/null

# Add to crontab
(crontab -l 2>/dev/null | grep -v start_redroid; \
 echo "@reboot /home/ubuntu/start_redroid.sh >> /home/ubuntu/redroid.log 2>&1") | crontab -
```

## One-click install script

A complete `setup_redroid.sh` that performs all steps above is in `scripts/setup_redroid.sh`. Transfer to any ARM64 Ubuntu 22.04 server and run `bash setup_redroid.sh`.

## Pipeline integration (pipeline_redroid.py)

A full standalone pipeline `pipeline_redroid.py` is at `~/Agents/APK-Research/scripts/monitor/pipeline_redroid.py`. Key design points:

- **ADB**: Windows `adb.exe` through SSH tunnel, device `127.0.0.1:5555`
- **Install**: `adb.exe install -r 'C:\\path\\apk.apk'` (Windows backslash paths)
- **Launch**: Use `get_launch_activity()` (aapt dump badging → `launchable-activity`), NOT `monkey -c LAUNCHER` (fails on hardened APKs with exit -5)
- **Node extraction**: Poll `cat /sdcard/Android/data/<pkg>/files/sdk_forwarder_fixed.json` every 5s, max 30s. JSON appears in ~5s. No root needed.
- **Fallback**: `/proc/PID/net/tcp` with Google/CDN IP filtering (no port restriction — proxy nodes may use 443)
- **Artifacts**: Same as cloud-phone pipeline (sdk_cache/.dat/uuid/forward)
- **HTML**: Standalone `generate_html()` — today-only APKs, Huawei-only detail table, lightbox screenshots
- **Huawei IP diff**: Save old IPs to `/tmp/old_hw_ips_redroid.json`, compare on each report
- **DB**: `proxy_monitor_db_redroid.json`, state: `apk_state_redroid.csv`
- **Domain list input**: Supports both CSV (with `pre_host` column) and .txt files (one domain per line, skip `pre_host` header). For .txt: use `for line in f: d = line.strip(); if d == 'pre_host' or not d: continue`
- **APK directory**: APKs may be in root of date folder (e.g. `20260804/`) not in an `apks/` subdirectory. Set `APK_DIR = WIN_BASE` (root) or `APK_DIR = f"{WIN_BASE}/apks"` (subdirectory) as appropriate
- **Per-date suffix**: For each new date batch, add `_YYYYMMDD` suffix to DB/state/history filenames to avoid mixing with previous runs

## Hardened APK launch activity discovery on Redroid

Hardened APKs (加固壳) on Redroid may have different Activity availability than on cloud phones. Confirmed behavior (2026-08-04):

1. `aapt dump badging` may NOT show `launchable-activity` for some APKs — the line is missing entirely
2. `dumpsys package <pkg> | grep LaunchActivity` finds the real Activity (e.g. `qya.nnginrkd.yldxmedix.VintageIcon`)
3. BUT `am start -n <pkg>/<activity>` may return "Activity class does not exist" even though dumpsys shows it registered
4. `monkey -p <pkg> -c LAUNCHER 1` also returns exit -5 (no activities found)

This means some APKs CANNOT be manually launched on Redroid (the hardened shell's dex loading doesn't complete in the time between install and launch). However, the pipeline (`pipeline_redroid.py`) still successfully obtains `sdk_forwarder_fixed.json` for these same APKs because:
- The pipeline installs, immediately launches via `get_launch_activity()` (which tries aapt first, then dumpsys), then polls for JSON every 5s
- The hardened shell may complete dex loading during the 3s sleep or within the first polling cycle
- Manual testing (install → wait → start → check) has a different timing that triggers the "Activity does not exist" race condition

**Takeaway**: Don't manually test individual APKs on Redroid to verify forward file generation — the pipeline's automated flow has better timing. If you need to verify, run the full pipeline and check the artifacts afterward.

## Display / Screenshot limitation (moved below)

Redroid has `swiftshader` (software rendering) but screenshots may be **white/blank** in some configurations. However, with `androidboot.redroid_gpu_mode=guest androidboot.redroid_width=1080 androidboot.redroid_height=1920` parameters, screenshots CAN produce content (58KB PNGs with 1080x1920 resolution, pixel range 30-255). Without the GPU mode parameter, screenshots are pure white/black (25KB).

**Confirmed**: APKs launched with `am start -n pkg/LaunchActivity` + 15-20 second wait produce meaningful screenshots (57-58KB) on Redroid with GPU mode=guest. Screenshots taken too early (immediately after launch) or after APP is force-stopped/uninstalled are blank (17-25KB).

- For production: skip screenshot collection or accept that quality varies — content depends on APP rendering timing and GPU mode
- The `generate_html()` in `pipeline_redroid.py` wraps `img_b64()` in try/except to handle truncated/white images
- Cloud phone (多多云) has a real virtual display and produces reliable screenshots — use that if screenshots are critical

## IP rate limiting on Redroid (CONFIRMED — Tencent Cloud gets rate-limited)

**Updated 2026-08-04**: Redroid on Tencent Cloud (exit IP 175.178.184.44, Guangzhou telecom) **IS rate-limited** by the APK control plane. After ~12 successful APKs, subsequent APKs fail to generate `sdk_forwarder_fixed.json` — only 52% success rate (12/23 APKs got forward files, 11 got only TCP fallback IPs with ports like `14.215.183.199:443`).

**Rate limiting comparison across all environments** (exhaustive testing):

| Environment | Exit IP | IP Type | Forward file success | Verdict |
|-------------|---------|---------|----------------------|---------|
| 多多云手机 (LXC) | 14.18.243.75 | Datacenter NAT (rotating) | **100%** (199/199) | ✅ Definitive |
| Redroid Tencent Cloud | 175.178.184.44 | Cloud server (fixed) | **52%** (12/23) | ❌ Rate-limited |
| WiFi (no proxy) | 58.153.46.2 | Personal broadband | **3.5%** (10/280) | ❌ Severely limited |
| Clash Meta VPN + TW | Taiwan IP | Overseas proxy | 0% | ❌ Foreign IP rejected |

**Key finding**: The control plane distinguishes between:
1. **Datacenter NAT with rotating IPs** (多多云) → NOT rate-limited (each request may exit from different IP)
2. **Fixed cloud server IP** (Tencent Cloud ECS) → Rate-limited, PROGRESSIVELY WORSENING
3. **Personal broadband** → Rate-limited after ~10 APKs
4. **Overseas IP** (Taiwan proxy) → APP enters UI but forwarder control rejected entirely

**Rate limiting is PROGRESSIVE — gets worse over time** (confirmed 2026-08-04 production run, 84 APKs total):

| APKs installed | Forward file success rate | Trend |
|----------------|--------------------------|-------|
| 0-12 | 52% (12/23) | Initial — some APKs already fail |
| 13-32 | 59% (19/32) | Slight recovery (different APK labels) |
| 33-74 | 28% (21/74) | Severe degradation |
| 75-84 | 26% (22/84) | Near-total block |

This is NOT a fixed threshold ("after 12 APKs") — the control plane accumulates registrations from the same IP and progressively blocks more. After ~70+ APKs from the same IP, success drops to ~26%.

**Recommendation**: Use 多多多云手机 for production runs (100% success, zero rate limiting, 413/662 APKs confirmed). Redroid is 15x faster (16s vs 245s per APK) but rate-limited progressively — only suitable for small batches (<10 APKs per server) or when combined with IP rotation (multiple servers / elastic IPs / changing public IP every ~10 APKs).

If using Redroid for large batches: allocate multiple servers, rotate after ~10 APKs per server, or use Tencent Cloud elastic IP to change public IP periodically.

**Rate limiting may partially reset between runs (2026-08-04 observation)**: Starting a fresh batch (20260804, 57 new APKs) on the same Redroid instance that had 84 APKs from the 20260728 batch (26% success), the first 23 APKs of the new batch showed 96% success (22/23 got forward files). This suggests either: (a) rate limiting decays over time (days between runs), (b) different APK batches connect to different control plane servers with different rate limiting, or (c) the control plane resets counters after a cooldown period. If confirmed, this means Redroid CAN be used for larger batches by spacing runs across multiple days — not just rotating IPs.

### test-keys vs release-keys hypothesis (unconfirmed)

Redroid uses `userdebug/test-keys` signature (AOSP build), while 多多云 uses `user/release-keys` (real OEM firmware). The control plane may detect `test-keys` as non-genuine device and reject forwarder control. This is an ALTERNATIVE hypothesis to IP-based rate limiting — both could be factors. To test: flash a `release-keys` system image onto Redroid (e.g., from a real Huawei EMUI firmware dump) and check if success rate improves.

**Huawei firmware resources**: `https://professorjtj.github.io/v2/` (Huawei Firm Finder v2 — has searchable model/version/region filters, better than v1 at `/`) catalogs EMUI firmware by model/region/version. Search for "MRD-AL00" + "9.1.0.299" yields 10+ variants (C00E130R2P2, C00E151R2P2, etc.) with Base/Cust/Preload package details (e.g., Base: MRD-LGRP1-CHN 9.1.0.299, Cust: MRD-AL00-CUST 9.1.0.130(C00), Preload: MRD-AL00-PRELOAD 9.0.1.2(C00R2)). Exact version 9.1.1.67 was NOT found.

**CRITICAL PITFALL — HiSuite-Proxy requires a physical Huawei phone**: The "Add Rom" button on Huawei Firm Finder sends download tasks to `http://127.0.0.1:7777/addROM.txt`, which is served by HiSuite-Proxy — a MODIFIED version of Huawei HiSuite (华为手机助手), NOT a standalone firmware downloader. HiSuite-Proxy.exe (50MB, downloaded from `https://github.com/ProfessorJTJ/HISuite-Proxy/releases/download/3.0/HiSuite_11.0.0.610_OVE.exe`) installs as a full HiSuite application. It REQUIRES a physical Huawei phone connected via USB to function — without a device, HiSuite cannot initiate firmware download and the "Add Rom" button silently fails (no error, no UI feedback). The download URL is never generated because HiSuite's authorize.action API call to `query.hicloud.com:443` needs a `deviceCertificate` that only exists on a real Huawei device.

**Huawei firmware download API flow** (from HiSuite-Proxy source code analysis):
1. HiSuite sends POST to `https://query.hicloud.com:443/sp_ard_common/v1/authorize.action` with device certificate
2. Server returns firmware download URL on `update.dbankcdn.com/TDS/data/files/`
3. HiSuite downloads `update_full_base.zip` (1.7GB)
4. Inside is `UPDATE.APP` — extract with HuaweiFirmwareExtractor (Python, zero-dep: `https://github.com/Natsume324/HuaweiFirmwareExtractor`)
5. Extract `system.img` → convert to ext4 → use as Redroid rootfs

**Without a Huawei phone, you CANNOT get past step 1.** The `authorize.action` API returns `data=&sign=&cert=` (empty) without a valid device certificate. Direct API calls (tried with XML, JSON, various Content-Types) all return empty — the server requires the certificate.

**Confirmed: HiSuite-Proxy is the ONLY way to download Huawei firmware.** Huawei Firm Finder v1 (`professorjtj.github.io`) "Files List" also routes through `http://127.0.0.1:7777/getFile.txt` — same HiSuite-Proxy dependency. No public direct-download links exist for Huawei firmware.

**Alternative paths (all untested)**:
1. Buy a cheap secondhand Huawei phone (MRD-AL00 ~100-200 RMB) — use once to download firmware, then no longer needed
2. Find third-party sites/forums (XDA, Baidu网盘) where users have shared extracted `system.img` or `update.app` files
3. Use Redroid 9.0.0 + modify `build.prop` to fake EMUI identity (`ro.build.brand=HUAWEI`, `ro.build.model=MRD-AL00`, `ro.build.fingerprint=HUAWEI/MAR-AL00/...`, `ro.build.version.emui=9`) — untested, may not bypass control-plane checks
4. Accept that Huawei firmware extraction is blocked without hardware access — continue using 多多云 cloud phone (100% success)

## Redroid 9.0.0 image availability

Redroid has Android 9.0.0 (`redroid/redroid:9.0.0-latest` and `9.0.0-240527`) on Docker Hub. Pull with: `sudo docker pull redroid/redroid:9.0.0-latest`. This is the closest to EMUI 9 (which is based on Android 9) if you want to test whether Android version matters for rate limiting. Full image list (as of 2026-08-04): 9.0.0, 10.0.0, 11.0.0, 12.0.0, 13.0.0, 14.0.0, 15.0.0, 16.0.0 — all available in `_latest` and dated variants.

## Performance comparison

| Method | Install/APK | Get JSON | Total | 662 APKs | Screenshots |
|--------|------------|----------|-------|----------|-------------|
| 多多云手机 (LXC) | 230s | 12s | 245s | ~44 hours | Yes (real display) |
| Redroid (Docker) | 10s | 6s | 16s | ~3 hours | No (white/blank) |

## Why cloud-phone IP doesn't trigger rate limiting

Cloud-phone (多多云) runs in an IDC datacenter — the NAT exit IP (e.g., 14.18.243.75) is a telecom datacenter IP. APK control-plane servers don't rate-limit datacenter IPs, only personal broadband IPs (e.g., 58.153.46.2 WiFi). Redroid on a cloud server has the same advantage.

## Pitfalls

1. **ashmem.ko crashes the kernel** — Do NOT load `drivers/staging/android/ashmem_linux.ko`. It causes an immediate kernel panic on Ubuntu 22.04 ARM64. Redroid 10 works without it.

2. **GitHub is blocked in China** — Can't `git clone` binder_linux. Must compile from the kernel-source package (`/usr/src/linux-source-*.tar.bz2`) which is available via Ubuntu mirrors.

3. **STACKPROTECTOR_PER_TASK build failure** — `make M=drivers/android modules` fails with `missing argument to -mstack-protector-guard-offset=`. Fix: temporarily comment out the `ifeq STACKPROTECTOR_PER_TASK` block in `arch/arm64/Makefile`, run `make modules_prepare`, then restore. The `asm-offsets.h` generated by `modules_prepare` contains the `TSK_STACK_CANARY` value needed.

4. **`monkey -c LAUNCHER` fails on hardened APKs** — Returns exit -5 (no Activity found). Hardened APKs (加固壳) have obfuscated Activity names. Use `dumpsys package <pkg> | grep LaunchActivity` to find the real class, then `am start -n pkg/Activity`.

5. **Cloud server port 5555 blocked by security group** — Tencent Cloud security groups block inbound 5555. Use SSH local tunnel (`-L 5555:127.0.0.1:5555`) instead of opening the port.

6. **`subprocess.run([''])` in Python causes PermissionError** — When adb commands time out, the fallback `subprocess.run([''])` crashes with `PermissionError: [Errno 13] Permission denied: ''`. Fix: return a dummy object `class R: stdout=''; stderr=''; returncode=-1` instead.

7. **Server reboot clears /tmp** — Kernel source and compiled .ko in /tmp are lost on reboot. Always `cp *.ko ~/` to persistent storage. The crontab @reboot script handles re-loading.

8. **daemon.json quoting** — Shell `echo` with JSON quotes gets mangled. Always use `python3 -c "import json; json.dump(...)"` to write daemon.json.

9. **SSH tunnel silently drops** — When the SSH tunnel dies, `adb.exe connect` gets "Connection refused" but the pipeline doesn't detect it — all subsequent installs show "安装失败(0.0s)" (0-second = device not found). Must: (a) run tunnel as background process with `ServerAliveInterval=30`, (b) periodically check `adb.exe devices` output for device presence, (c) if disconnected, restart tunnel + `adb.exe kill-server && adb.exe start-server && adb.exe connect`.

10. **Redroid container restart loses state** — Docker container with `-v ~/redroid-data:/data` persists APP data across restarts, but the binder module must be re-loaded (`insmod`) and binderfs re-mounted before `docker start redroid`. The `@reboot` crontab script handles this, but manual restarts require the same sequence.

## TCP vs Forward file IP verification

To verify that `sdk_forwarder_fixed.json` IPs match actual network connections, read `/proc/PID/net/tcp` while the APP is running and compare. Results confirmed: forward file has 13 IPs, TCP has 3-4 active connections, with ~1 IP in common. The forward file is validated as the correct source for proxy node IPs. See `references/tcp-forward-comparison.md` for full implementation and analysis.

## Cross-variant .dat URL prediction (dh151 → dh183)

The bucket/filename derivation algorithm `md5(YYYYMMDD + app_name + cloud_tag + sdk_version)` works across variants. The 20260804 batch uses `app_name=dh183` (port 30183), confirmed 16/16 against known `sdk_cache.json` URLs. RSA private key extraction works the same way (search for `LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ` in `libgojni.so`). However, the AES key differs per variant — the dh151 key fails on dh183 .dat files. Bootstrap seed (in Java/DEX, not in .so) must be extracted via memory dump脱壳 to get the new AES key. See `references/dat-bucket-derivation-and-cross-variant.md` for full details and the reference analysis at `/home/ninini/Agents/AI-APK/reports/exdyfb_unpacked/`.

## Files in this skill

- `scripts/setup_redroid.sh` — One-click install script for ARM64 Ubuntu 22.04
- `scripts/start_redroid.sh` — Reboot auto-start script (crontab @reboot)
- `references/pipeline_redroid.md` — Pipeline integration notes (ADB path, Activity detection, artifact collection)
- `references/tcp-forward-comparison.md` — TCP connection vs forward file IP verification technique and results
- `references/dat-bucket-derivation-and-cross-variant.md` — Cross-variant (dh151/dh183) .dat URL prediction and AES key derivation status
