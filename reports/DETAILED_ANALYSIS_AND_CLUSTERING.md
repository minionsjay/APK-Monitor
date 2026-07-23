# Android 恶意 APK 分析操作手册（从零开始）

**编写日期**: 2026-07-20
**样本目录**: `/home/ninini/Agents/AI-APK/samples/0401/` (36 个 APK, 2.4GB)
**分析环境**: WSL2 Ubuntu 22.04 + Docker 29.6.2 + Pixel 4 (Android 13, root via Magisk)
**目标读者**: 对 Android 逆向有基础了解但不熟悉具体操作的分析人员

本文档记录了对 36 个 APK 进行恶意软件分析的**每一步操作**，包括所用命令、源码位置、工具安装方式、以及为什么这样做。跟着步骤走可以完整复现整个分析过程。

---

# 目录

1. [环境准备](#1-环境准备)
2. [第一步：批量扫描——找出哪些 APK 是恶意的](#2-批量扫描)
3. [第二步：DNS TXT C2 家族深入分析（14 个 APK）](#3-dns-txt-c2-家族)
4. [第三步：RustDesk 远程控制分析（11 个 APK）](#4-rustdesk-分析)
5. [第四步：Telegram 改造恶意 IM 分析（4 个 APK）](#5-telegram-im-分析)
6. [第五步：其他恶意 APK 分析](#6-其他恶意-apk)
7. [第六步：动态脱壳——用 Frida 从手机内存中提取加密的代码](#7-动态脱壳)
8. [第七步：运行时行为监控——用 Frida hook 抓取实时行为](#8-运行时行为监控)
9. [第八步：聚类分析与跨家族关联](#9-聚类分析)
10. [所有工具源码清单](#10-工具源码清单)

---

# 1. 环境准备

## 1.1 WSL2 环境

```bash
# 检查 WSL2 Ubuntu 版本
cat /etc/os-release | grep VERSION=
# 预期输出: VERSION="22.04.5 LTS"

# 检查 systemd 是否启用
ps -p 1 -o comm=
# 预期输出: systemd (如果是 "init" 则需要启用 systemd)
```

## 1.2 安装 Docker（静态二进制方式，不用 apt）

为什么不用 `apt-get install docker-ce`？因为在 WSL2 中 apt 源可能有 GPG 问题或网络超时。用清华镜像下载静态二进制更可靠。

```bash
# 下载 Docker 29.6.2 静态二进制（从清华镜像）
mkdir -p ~/docker-install && cd ~/docker-install
wget https://mirrors.tuna.tsinghua.edu.cn/docker-ce/linux/static/stable/x86_64/docker-29.6.2.tgz
tar xzf docker-29.6.2.tgz

# 安装（需要 sudo，密码是 0）
sudo cp docker/* /usr/bin/
sudo cp docker/containerd /usr/bin/

# 创建 systemd 服务文件
sudo tee /etc/systemd/system/containerd.service > /dev/null << 'EOF'
[Unit]
Description=containerd container runtime
After=network.target

[Service]
ExecStart=/usr/bin/containerd
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/docker.service > /dev/null << 'EOF'
[Unit]
Description=Docker Application Container Engine
After=network.target containerd.service

[Service]
Type=notify
ExecStart=/usr/bin/dockerd --containerd=/run/containerd/containerd.sock
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 启动 Docker
sudo systemctl daemon-reload
sudo systemctl enable --now docker
sudo systemctl enable --now containerd

# 验证
docker --version
# 预期: Docker version 29.6.2
```

## 1.3 安装 Docker Compose

```bash
# 下载 Compose v2.30（通过 GitHub 代理）
cd ~/docker-install
wget https://ghfast.top/https://github.com/docker/compose/releases/download/v2.30.0/docker-compose-linux-x86_64
sudo mkdir -p /usr/libexec/docker/cli-plugins
sudo cp docker-compose-linux-x86_64 /usr/libexec/docker/cli-plugins/docker-compose
sudo chmod +x /usr/libexec/docker/cli-plugins/docker-compose

# 配置国内镜像加速器（防止 docker.io 拉取超时）
sudo tee /etc/docker/daemon.json > /dev/null << 'EOF'
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://dockerproxy.com",
    "https://docker.nju.edu.cn",
    "https://docker.mirrors.ustc.edu.cn"
  ]
}
EOF

# 重启 Docker
sudo systemctl restart docker

# 验证
docker compose version
# 预期: Docker Compose version v2.30.0
```

## 1.4 安装 Python 依赖

```bash
pip install pycryptodome xxtea-py androguard frida frida-tools
```

这些包的用途：
- `pycryptodome`: AES 加密/解密（用于解密 C2 配置）
- `xxtea-py`: XXTEA 算法（第 4 层解密）
- `androguard`: APK 解析（提取包名、权限、Activity）
- `frida` / `frida-tools`: 动态脱壳和运行时 hook

## 1.5 准备 Android 设备

```bash
# 检查设备是否连接
adb devices -l
# 预期输出类似:
# List of devices attached
# 192.168.1.16:38493     device product:flame model:Pixel_4

# 检查 Android 版本和架构
adb shell getprop ro.build.version.release   # 预期: 13
adb shell getprop ro.product.cpu.abi         # 预期: arm64-v8a

# 检查 root 状态（需要 Magisk）
adb shell "su -c id"
# 预期: uid=0(root)

# 检查 Frida server 是否运行
adb shell "ps -A | grep frida"
# 预期: root xxxxx frida-server
# 如果没有，需要推送 frida-server 到设备并启动
```

## 1.6 sg docker vs newgrp docker

在 WSL 中运行 Docker 命令时，用 `sg docker -c '命令'` 而不是 `newgrp docker`。原因：`newgrp` 会启动登录 shell，触发 conda 初始化导致报错；`sg` 只切换 docker 用户组，不触发登录脚本。

```bash
# 正确方式
sg docker -c 'docker ps'

# 错误方式（会触发 conda 报错）
newgrp docker
```

---

# 2. 批量扫描——找出哪些 APK 是恶意的

## 2.1 目标

对 36 个 APK 做快速扫描，找出哪些属于已知恶意软件家族。

## 2.2 扫描脚本

源码位置: `/home/ninini/Agents/AI-APK/samples/0401/scan_malware.py`

扫描原理：用 Python 的 `zipfile` 库打开 APK（APK 本质是 ZIP 文件），读取所有 `classes*.dex` 文件的字节，搜索已知的恶意软件特征字符串。

```bash
# 运行批量扫描
cd /home/ninini/Agents/AI-APK/samples/0401
python3 scan_malware.py 2>&1
```

脚本核心逻辑（简化版）：

```python
import zipfile, os

SAMPLES_DIR = "/home/ninini/Agents/AI-APK/samples/0401"

# 已知的恶意软件特征字符串（在 dex 字节中搜索）
INDICATORS = [
    b"NetworkConstant",     # C2 配置类名
    b"AppProtectManager",   # C2 控制器类名
    b"stringfog",           # 字符串混淆库
    b"APM6986",             # 加密数组类名
    b"org/xbill/DNS",       # dnsjava 库（DNS TXT 查询）
    b"BW-755-",             # DGA 种子前缀
    b"kWYoedTL",            # StringFog XOR 密钥
    b"sdfkjn755fvb",       # OSS 基域名
    b"rustdesk",            # RustDesk 远程控制
    b"librustdesk",         # RustDesk native 库
]

for apk_file in sorted(os.listdir(SAMPLES_DIR)):
    if not apk_file.endswith(".apk"):
        continue
    apk_path = os.path.join(SAMPLES_DIR, apk_file)
    found_indicators = []
    
    with zipfile.ZipFile(apk_path) as zf:
        for dex_name in [n for n in zf.namelist() if n.endswith(".dex")]:
            try:
                dex_data = zf.read(dex_name)  # 读取 dex 文件字节
            except RuntimeError:
                # dex 被 ZIP 加密，跳过
                continue
            
            for indicator in INDICATORS:
                if indicator in dex_data and indicator not in found_indicators:
                    found_indicators.append(indicator.decode())
    
    # 如果找到 2 个以上指标，判定为恶意
    is_malicious = len(found_indicators) >= 2
    print(f"{'🔴' if is_malicious else '⚪'} {apk_file} indicators={found_indicators}")
```

## 2.3 扫描结果

运行后得到 36 行输出。关键发现：
- 13 个 APK 匹配 DNS TXT C2 家族指标
- 10 个 APK 包含 `librustdesk.so`
- 4 个 APK 基于 Telegram 改造（后续子 agent 发现）
- 1 个 APK 是贷款诈骗
- 1 个 APK 非恶意
- 7 个 APK 需要进一步分析

## 2.4 为什么要扫描所有 dex 文件

APK 可以包含多个 dex 文件（classes.dex, classes2.dex, ..., classes6.dex）。恶意代码可能藏在第 4 或第 5 个 dex 里。如果只扫第一个，会漏掉。所以必须扫描所有 dex：

```python
for dex_name in [n for n in zf.namelist() if n.endswith(".dex")]:
    # 不要只扫 classes.dex，要扫所有 classes*.dex
```

同时要处理 ZIP 加密的 dex（`RuntimeError`）：

```python
try:
    dex_data = zf.read(dex_name)
except RuntimeError:
    # dex 被 ZIP 加密了，无法读取
    # 后面用 Frida 动态脱壳
    continue
```

---

# 3. DNS TXT C2 家族深入分析（14 个 APK）

这是最核心的分析。14 个 APK 使用了 4 层加密来隐藏 C2 服务器地址。

## 3.1 加密链路概述

```
第 1 步: 从 APK 中提取 NetworkConstant.k（一个很长的 base64 字符串）
第 2 步: base64 解码 k → 得到内层 base64 字符串
第 3 步: AES-256-ECB 解密 → 得到管道分隔的配置文本
第 4 步: 从配置文本中提取 3 个 dnsGroup 域名
第 5 步: 向这些域名发起 DNS TXT 查询 → 得到加密的 C2 配置
第 6 步: AES-256-ECB 解密 TXT 记录 → 得到 C2 IP:端口
```

## 3.2 第一步：从 APK 中提取 NetworkConstant.k

NetworkConstant 是一个 Java 类，里面有一个叫 `k` 的字段，值是一个很长的 base64 字符串。

**方法 A：用 jadx 反编译 APK，查看 Java 源码**

```bash
# 用 Docker 容器里的 jadx 反编译（因为 WSL 主机上没有安装 jadx）
cd /home/ninini/Agents/APK-Research/AgenticAPKFlow
sg docker -c 'docker run --rm -v /home/ninini/Agents/AI-APK/samples/0401:/samples -v /tmp:/out --entrypoint jadx agenticapkflow-agentic-apk:latest -d /out/jadx_output /samples/DF165C93BFA4110923A73A467F14522F*.apk'

# 查看反编译后的 NetworkConstant.java
cat /tmp/jadx_output/sources/im/vttzngszmt/network/NetworkConstant.java
```

你会看到类似这样的代码：

```java
public class NetworkConstant {
    public static final String OSS_URL = "sdfkjn755fvb.com";
    public static final String PORT = "31818";
    public static final String ENABLE_SETTING = "BW-755-";
    public static final String k = "SDRwYUM3aDE5cnNPKzRxM2xT...";  // ← 这个就是加密的 C2 配置
}
```

**方法 B：用 Python 从 dex 字节中直接搜索（不需要反编译）**

当 APK 的 dex 被加密时，jadx 无法反编译。这时需要先脱壳（见第 7 节），然后用 Python 搜索脱壳后的 dex：

```python
import base64, os, re

def find_b64_strings(data, min_len=200):
    """在二进制数据中找长的 base64 字符串"""
    results = []
    i = 0
    while i < len(data):
        if (0x41 <= data[i] <= 0x5A or    # A-Z
            0x61 <= data[i] <= 0x7A or    # a-z
            0x30 <= data[i] <= 0x39 or    # 0-9
            data[i] in (0x2B, 0x2F, 0x3D)):  # +, /, =
            start = i
            while i < len(data) and (0x41 <= data[i] <= 0x5A or
                   0x61 <= data[i] <= 0x7A or 0x30 <= data[i] <= 0x39 or
                   data[i] in (0x2B, 0x2F, 0x3D)):
                i += 1
            run = data[start:i]
            if len(run) >= min_len:
                results.append(run.decode("ascii"))
        else:
            i += 1
    return results

# 搜索脱壳后的 dex 文件
dex_dir = "/home/ninini/Agents/APK-Research/dumped_dex/187689"
for dex_name in sorted(os.listdir(dex_dir)):
    data = open(os.path.join(dex_dir, dex_name), "rb").read()
    for s in find_b64_strings(data, 200):
        try:
            decoded = base64.b64decode(s + "=" * (-len(s) % 4))
            # 检查是否是双重 base64（解码后还是 base64）
            if len(decoded) > 500 and all(b < 128 for b in decoded):
                inner_str = decoded.decode("ascii", errors="replace")
                if re.match(r'^[A-Za-z0-9+/=]+$', inner_str):
                    print(f"Found k value in {dex_name}: {len(s)} chars")
        except:
            pass
```

**关键点**: `k` 值的特征是"双重 base64"——外层 base64 解码后，得到的还是另一个 base64 字符串。这是因为 `k` 在源码中已经被 base64 编码了一次，而 `k` 本身的值又是另一个 base64 字符串。

## 3.3 第二步：解密 k——推导 AES 密钥

解密 `k` 需要一个 AES-256 密钥。这个密钥不是硬编码的，而是从多个加密数组中派生出来的。

### 3.3.1 找到加密数组

在反编译后的代码中（`a/a/a/APM6986.java`），有 4 个数组（APM6988, APM6989, APM6990[0-2], APM6991），每个数组有 4 个元素，每个元素是一个 StringFog 加密的 base64 字符串。

### 3.3.2 StringFog XOR 解密（第 1 层）

StringFog 是一个开源的字符串混淆工具。它的原理是：先 base64 解码密文，然后用一个固定的 key 做 XOR。

```python
import base64

STRINGFOG_KEY = "kWYoedTLztHL7dHrsLy99mVu5SHKBgJF"  # 这个 key 在 APM6990.java 中

def stringfog_decrypt(cipher):
    """StringFog XOR 解密"""
    # base64 解码
    raw = base64.urlsafe_b64decode(cipher + "=" * (-len(cipher) % 4))
    # XOR
    out = bytearray(raw)
    for i in range(len(out)):
        out[i] ^= ord(STRINGFOG_KEY[i % len(STRINGFOG_KEY)])
    return out.decode("utf-8")
```

### 3.3.3 AES 密钥派生（SHA-256）

在 `APM6986.java` 中有 3 个种子字符串（也是 StringFog 加密的）：

```python
# 解密种子（先 StringFog XOR，得到 base64 编码的种子）
S1 = base64.b64decode("eW5HM1JzUDlXcnQ0").decode()  # "ynG3RsP9Wrt4"
S2 = base64.b64decode("Nm1LZjJYaDhRdjdM").decode()  # "6mKf2Xh8Qv7L"
S3 = base64.b64decode("VGw1QnoxQzZOcDNK").decode()  # "Tl5Bz1C6Np3J"

# SHA-256 派生密钥
import hashlib
digest = hashlib.sha256((S1 + S2 + S3).encode()).digest()

# 关键：不是取 hex digest 的前 32 字符，而是取 Base64 编码后的前 32 字符！
aes_key32 = base64.b64encode(digest).decode()[:32]
# 结果: "Na0PzT8Aj44aIGXqWlyWcKQ10R67UnjV"
```

**为什么是 Base64 前 32 而不是 hex 前 32？** 因为 Java 代码中用的是 `Base64.encode(sha256(...))` 而不是 `Hex.encode(sha256(...))`。这个细节是逆向分析中最容易踩坑的地方——如果用 hex，得到的密钥完全不同，AES 解密会失败。

### 3.3.4 AES-256-ECB 解密（第 2 层）

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 从 APM6989 数组的 4 个元素解密后拼接得到
K_AES_KEY = "qRXdx78YqrwMZSz6sboSPgbAoREjIeZa"  # 32 字符 = 32 字节 = AES-256

# 解密 k
step1 = base64.b64decode(k_value).decode("utf-8")  # 外层 base64 解码
ct = base64.b64decode(step1)                        # 内层 base64 解码 → 密文
cipher = AES.new(K_AES_KEY.encode("utf-8"), AES.MODE_ECB)
pt = cipher.decrypt(ct)
pt = unpad(pt, 16)  # 去除 PKCS5 padding
text = pt.decode("utf-8", errors="replace")
```

### 3.3.5 XXTEA 解密（第 4 层，用于数组元素）

APM6989/6990 数组的每个元素需要 4 层解密：StringFog → AES → base64.decode → XXTEA。

```python
import xxtea  # pip install xxtea-py

XXTEA_KEY16 = "Na0PzT8Aj44aIGXq"  # AES key32 的前 16 字符

def decrypt_array_element(cipher_str):
    """完整 4 层解密"""
    # 第 1 层: StringFog XOR
    inner = stringfog_decrypt(cipher_str)
    # 第 2 层: AES-256-ECB
    ct1 = base64.b64decode(inner)
    aes_pt = aes_ecb_decrypt(ct1, AES_KEY32)
    pt_str = aes_pt.decode("utf-8", errors="replace")
    # 第 3 层: base64 解码
    ct2 = base64.b64decode(pt_str + "=" * (-len(pt_str) % 4))
    # 第 4 层: XXTEA
    plain = xxtea.decrypt(ct2, XXTEA_KEY16.encode())
    return plain.decode("utf-8", errors="replace")
```

**为什么 XXTEA 用 `xxtea-py` 库而不是自己实现？** 因为自己实现 XXTEA 时，Java 的 `int` 是 32 位有符号整数，Python 的 `int` 是大整数。位移操作需要手动 mask 到 32 位。`xxtea-py` 是 C 扩展，和 Java 的实现一致，避免了这个问题。

## 3.4 完整的解密工具

源码位置: `/home/ninini/Agents/APK-Research/dns_txt_c2_decryptor.py`

这个工具封装了上面所有步骤，可以自动分析任意 APK：

```bash
# 单个 APK 分析（提取 + 解密 C2 配置）
python3 /home/ninini/Agents/APK-Research/dns_txt_c2_decryptor.py /path/to/sample.apk

# 单个 APK + 实际 DNS TXT 查询（获取实时 C2 IP）
python3 /home/ninini/Agents/APK-Research/dns_txt_c2_decryptor.py /path/to/sample.apk --query-dns

# 批量分析整个目录
python3 /home/ninini/Agents/APK-Research/dns_txt_c2_decryptor.py /home/ninini/Agents/AI-APK/samples/0401 --query-dns
```

输出示例：
```
🔴 DF165C93BFA4110923A73A467F14522F.apk (79MB) indicators=12 c2=10
🔴 184618.apk (88MB) indicators=10 c2=10
⚪ 187702.apk (10MB) indicators=0 c2=0
...
=== Summary ===
Total: 36, Family: 13
Total C2 endpoints: 120
Unique C2 IPs: 110
```

## 3.5 第三步：DNS TXT 查询

解密 `k` 后得到 3 个 dnsGroup 配置，每个包含一个域名和 2 个 DNS server。必须用指定的 DNS server 查询（不是系统默认的），因为 TXT 记录可能只在这些 DNS server 上有。

```bash
# dnsGroup 0: 用 119.29.29.29 (DNSPod) 查询
dig +short @119.29.29.29 TXT QPAdvdJjeg7MXTJ.51island.vip

# dnsGroup 1: 用 114.114.114.114 (114DNS) 查询
dig +short @114.114.114.114 TXT 25NvMILWRkN4F.68pulse.xyz

# dnsGroup 2: 用 223.5.5.5 (阿里 AliDNS) 查询
dig +short @223.5.5.5 TXT rQAAmN6L9G8M.68pulse.xyz
```

每个查询返回一个 base64 编码的加密字符串，例如：
```
"z4lp5+tV7OuKrSl1icdTEa0wvqOISb+WuB80FhByF79X5B/wzzNaqfP7umnUACqm7hRsEgmlvgKgSKoTy3+OuG+HKBtUi..."
```

## 3.6 第四步：解密 TXT 记录得到 C2 IP

每个 dnsGroup 的 TXT 记录用不同的 AES 密钥解密：

```python
# dnsGroup 0 的 AES key（来自 APM6990[0] 数组解密）
txt_key_0 = "445XeO2RtBUJgZMPku7SOwzGwAqiAlAZ"

# dnsGroup 1 的 AES key
txt_key_1 = "RKwifmZxHVaECYF0rxwuEZTLDy7ofjAY"

# dnsGroup 2 的 AES key
txt_key_2 = "50mUJ3qy9eOk3WH5xgUPUUdduwiv7yGv"

# 解密
ct = base64.b64decode(txt_record_b64)
cipher = AES.new(txt_key.encode("utf-8"), AES.MODE_ECB)
pt = cipher.decrypt(ct)
pt = unpad(pt, 16)
text = pt.decode("utf-8")
# 结果: "3119624359,1851|813716623,2477|1113045822,3126|5539046253,8977|@f9u4Za"
```

解密后的格式是 `IP十进制,端口|IP十进制,端口|...|@token`

IP 是 32 位无符号整数的十进制表示。转换为标准 IP 格式：

```python
import struct, socket

ip_int = 3119624359
ip_str = socket.inet_ntoa(struct.pack("!I", ip_int))
# 结果: "185.241.176.167"

port = 1851
print(f"C2: {ip_str}:{port}")
# 结果: C2: 185.241.176.167:1851
```

有些 IP 整数超过 2^32（如 `5539046253`），需要取模：
```python
if ip_int > 4294967295:
    ip_int = ip_int % (2**32)
```

## 3.7 所有 7 个共享密钥汇总

这些密钥在所有 14 个 DNS TXT C2 家族 APK 中都是相同的（除 183651 升级版有额外的 DoH/DoT 密钥）：

| 密钥名 | 值 | 用途 |
|--------|-----|------|
| StringFog XOR key | `kWYoedTLztHL7dHrsLy99mVu5SHKBgJF` | 第 1 层：字符串混淆 XOR |
| AES key32 | `Na0PzT8Aj44aIGXqWlyWcKQ10R67UnjV` | 第 2 层：AES 密钥（SHA-256 派生）|
| XXTEA key16 | `Na0PzT8Aj44aIGXq` | 第 4 层：XXTEA 密钥（key32 前 16 字节）|
| k 解密 AES key | `qRXdx78YqrwMZSz6sboSPgbAoREjIeZa` | 解密 NetworkConstant.k |
| TXT grp0 AES key | `445XeO2RtBUJgZMPku7SOwzGwAqiAlAZ` | 解密 dnsGroup 0 的 TXT 记录 |
| TXT grp1 AES key | `RKwifmZxHVaECYF0rxwuEZTLDy7ofjAY` | 解密 dnsGroup 1 的 TXT 记录 |
| TXT grp2 AES key | `50mUJ3qy9eOk3WH5xgUPUUdduwiv7yGv` | 解密 dnsGroup 2 的 TXT 记录 |

---

# 4. RustDesk 远程控制分析（11 个 APK）

## 4.1 识别 RustDesk

RustDesk 是一个开源的远程桌面软件。攻击者把它嵌入到 Flutter 壳应用中，用作远程控制工具。

识别方法：检查 APK 中是否有 `librustdesk.so`：

```python
import zipfile

with zipfile.ZipFile("187712.apk") as zf:
    so_files = [n for n in zf.namelist() if n.endswith(".so")]
    for sf in so_files:
        if "rustdesk" in sf.lower():
            print(f"Found RustDesk: {sf}")
    # 同时检查是否有 Flutter
    has_flutter = any("libflutter.so" in n for n in zf.namelist())
    print(f"Flutter: {has_flutter}")
```

如果看到 `lib/arm64-v8a/librustdesk.so` + `lib/arm64-v8a/libflutter.so` + `lib/arm64-v8a/libapp.so`，就是一个 Flutter + RustDesk 的组合。

## 4.2 提取 C2 域名

C2 域名硬编码在 `librustdesk.so` 中（Rust 编译的二进制文件）。从 .so 文件中提取字符串：

```python
def extract_strings(data, min_len=5):
    """从二进制文件中提取可打印字符串"""
    results = []
    current = bytearray()
    for b in data:
        if 0x20 <= b <= 0x7e:  # ASCII 可打印字符范围
            current.append(b)
        else:
            if len(current) >= min_len:
                results.append(current.decode("ascii"))
            current = bytearray()
    if len(current) >= min_len:
        results.append(current.decode("ascii"))
    return results

import zipfile, re

with zipfile.ZipFile("187712.apk") as zf:
    so_data = zf.read("lib/arm64-v8a/librustdesk.so")
    strings = extract_strings(so_data, 5)
    
    # 搜索 URL
    for s in strings:
        if s.startswith("http://") and "login" in s:
            print(f"C2 URL: {s}")
            # 输出: http://tjylogin.vhyrz5.com:10500/AppInfo.aspx?s=rustdesk
```

## 4.3 RustDesk 分析工具

源码位置: `/home/ninini/Agents/AI-APK/samples/0401/analyze_rustdesk.py`

```bash
cd /home/ninini/Agents/AI-APK/samples/0401
python3 analyze_rustdesk.py 2>&1
```

输出每个 APK 的 C2 域名、构建变体、API 端点。

---

# 5. Telegram 改造恶意 IM 分析（4 个 APK）

## 5.1 识别方法

这些 APK 基于 Telegram 开源客户端改造。识别特征：
- `.so` 文件名包含 `libtmessages`（Telegram 的 native 网络库）
- dex 中包含 `org.telegram.messenger` 类名
- C2 域名 `m12345.com` 或 `nebulachat3.appspot.com`

```python
import zipfile

INDICATORS = [b"libtmessages", b"org.telegram", b"m12345", b"nebulachat"]

with zipfile.ZipFile("187693.apk") as zf:
    for dex_name in [n for n in zf.namelist() if n.endswith(".dex")]:
        data = zf.read(dex_name)
        for ind in INDICATORS:
            if ind in data:
                print(f"Found {ind.decode()} in {dex_name}")
```

## 5.2 187693 的危险组件

187693 是最危险的样本。通过搜索 dex 中的类名，发现：

- `VisualCallReceiveService` — 自动接听视频通话（被叫方监听）
- `AndroidScreenCapService` — 屏幕录制
- `OnePxActivity` — 1 像素 Activity 保活（防止进程被杀）
- `EmulatorCheckService` — 反模拟器检测
- `PhoneIntercepterService` — 电话拦截

这些类名直接在 dex 字节中搜索即可找到。

---

# 6. 其他恶意 APK 分析

## 6.1 贷款诈骗 (187732 "支付通" + 187697 "拍拍贷")

用 androguard 解析 Manifest（因为 Python zipfile 不支持 187732 的非标准压缩方法 0x3a54）：

```bash
python3 -c "
from androguard.misc import AnalyzeAPK
a, d, dx = AnalyzeAPK('/home/ninini/Agents/AI-APK/samples/0401/187732.apk')
print(f'Package: {a.get_package()}')
print(f'App name: {a.get_app_name()}')
print(f'Permissions: {a.get_permissions()}')
print(f'Activities: {a.get_activities()}')
print(f'Services: {a.get_services()}')
"
```

187697 "拍拍贷" 的伪装技巧：在应用名前面加了零宽字符（U+2061），让肉眼看到的名字是 "拍拍贷"，但字符串比较时和真实的 "拍拍贷" 不同，绕过应用商店的名称检测。

## 6.2 仿冒办公 IM (187721 "IN办公")

用 Python 搜索 dex 中的电话拦截相关类名和服务：

```python
import zipfile

with zipfile.ZipFile("187721.apk") as zf:
    for dex_name in [n for n in zf.namelist() if n.endswith(".dex")]:
        data = zf.read(dex_name)
        if b"PhoneIntercepter" in data:
            print(f"Found phone interceptor in {dex_name}")
        if b"socket.io" in data:
            print(f"Found websocket C2 in {dex_name}")
```

---

# 7. 动态脱壳——用 Frida 从手机内存中提取加密的代码

## 7.1 什么时候需要脱壳

当 APK 的 `classes.dex` 被 ZIP 加密时（`zipfile.getinfo(dex_name).flag_bits & 0x1` 为 True），无法用 jadx 反编译。这时需要在手机上运行 APP，趁 APP 运行时从内存中把解密后的 dex 提取出来。

## 7.2 安装 APK 到手机

```bash
# 安装 187689.apk
adb install -r /home/ninini/Agents/AI-APK/samples/0401/187689.apk

# 启动 APP
adb shell monkey -p guabtlu.pvgi.qcxmvajd -c android.intent.category.LAUNCHER 1

# 等待 5 秒让 APP 启动
sleep 5

# 获取进程 PID
adb shell pidof guabtlu.pvgi.qcxmvajd
# 输出: 778
```

## 7.3 用 frida-dexdump 脱壳

`frida-dexdump` 是一个 Frida 工具，它扫描进程的内存空间，找到所有以 "dex\n" 开头的内存块（这些就是解密后的 dex 文件），然后把它们导出。

```bash
# 安装 frida-dexdump
pip install frida-dexdump

# 创建输出目录
mkdir -p /home/ninini/Agents/APK-Research/dumped_dex/187689

# 脱壳（-U = USB 设备，-p PID = attach 到进程，-o = 输出目录）
frida-dexdump -U -p 778 -o /home/ninini/Agents/APK-Research/dumped_dex/187689
```

原理：Frida 注入到目标进程后，调用 `Process.enumerateRanges({prot: 'r--'})` 枚举所有可读的内存区域，然后在每个区域中搜索 DEX 文件头（`64 65 78 0a 30 33 35 00` = "dex\n035\0"），找到后读取 `file_size` 字段（偏移 0x20 处的 4 字节），按这个大小读取整个 dex，然后保存到文件。

## 7.4 脱壳结果

```
INFO:frida-dexdump:[+] DexMd5=..., SavePath=.../classes03.dex, DexSize=0xfb284
INFO:frida-dexdump:[+] DexMd5=..., SavePath=.../classes04.dex, DexSize=0x813c
...
INFO:frida-dexdump:[*] All done...
```

187689 脱壳得到 33 个 dex 文件，187702 脱壳得到 32 个 dex 文件。

## 7.5 在脱壳后的 dex 中搜索恶意指标

```bash
cd /home/ninini/Agents/APK-Research/dumped_dex/187689

# 搜索 DNS TXT C2 家族指标
for kw in "NetworkConstant" "AppProtectManager" "BW-755" "kWYoedTL" "sdfkjn"; do
  found=$(grep -l "$kw" *.dex 2>/dev/null | head -3)
  if [ -n "$found" ]; then
    echo "  $kw: $found"
  fi
done
```

发现 187689 包含所有 DNS TXT C2 家族指标 → 确认是同一家族。

---

# 8. 运行时行为监控——用 Frida hook 抓取实时行为

## 8.1 目标

在 APP 运行时监控它的网络连接、DNS 查询、文件访问等行为。

## 8.2 Frida 版本注意事项

**重要**: Frida 17.x 移除了 `Java` 全局对象。如果用 `Java.use('java.net.InetAddress')` 会报 `ReferenceError: 'Java' is not defined`。

解决方案：使用 **native hook（libc 级别的 hook）**，不需要 Java 桥接。Frida 17 的 `Interceptor.attach` 和 `Process.findModuleByName` 都可以正常使用。

**另一个重要点**: Frida 17 中 `Module.findExportByName` 被移除了。需要用 `Process.findModuleByName('libc.so').findExportByName('connect')` 代替。

## 8.3 hook 脚本

源码位置: `/home/ninini/Agents/APK-Research/hook_native3.py`

```bash
# 确保 APP 正在运行
adb shell pidof guabtlu.pvgi.qcxmvajd
# 如果没有运行，启动它
adb shell monkey -p guabtlu.pvgi.qcxmvajd -c android.intent.category.LAUNCHER 1
sleep 5

# 运行 hook
cd /home/ninini/Agents/APK-Research
python3 hook_native3.py
```

## 8.4 hook 脚本核心逻辑

```javascript
// Frida 17 native hook（不依赖 Java 桥接）

// 找到 libc.so 中的函数地址
function findExport(name) {
    var lib = Process.findModuleByName('libc.so');
    if (lib) return lib.findExportByName(name);
    return null;
}

// Hook connect() — 抓取所有 TCP 连接
var connect_ptr = findExport('connect');
Interceptor.attach(connect_ptr, {
    onEnter: function(args) {
        var sa = args[1];  // sockaddr 结构体指针
        var family = sa.readU16();  // 地址族
        if (family === 2) {  // AF_INET (IPv4)
            // 从 sockaddr_in 中提取 IP 和端口
            var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
            var ip = sa.add(4).readU8() + '.' +
                     sa.add(5).readU8() + '.' +
                     sa.add(6).readU8() + '.' +
                     sa.add(7).readU8();
            send({type: 'connect', ip: ip, port: port});
        }
    }
});

// Hook getaddrinfo() — 抓取 DNS 解析
var gai_ptr = findExport('getaddrinfo');
Interceptor.attach(gai_ptr, {
    onEnter: function(args) {
        var host = args[0].readCString();
        if (host && host.length > 3) {
            send({type: 'dns', host: host});
        }
    }
});
```

## 8.5 运行时发现

运行 hook 90 秒后，发现：

- 250 次 `connect()` 调用，全部指向 `127.0.0.1:31026`（本地代理端口）
- 没有 DNS 解析事件（因为 dnsjava 库用自带的 DNS 解析，不走 libc 的 `getaddrinfo`）
- 没有 exec/dlopen 事件

同时看 logcat：

```bash
adb logcat -d -t 500 | grep -iE "bond|dns|txt|game|shield|protect"
```

发现关键日志：
```
D bond: 链接状态：server 1
D bond: 游戏盾初始化 = 0
D tmessages: failed to get dns txt result
D tgnet: 游戏盾 connection连接：127.0.0.1:31026
```

这证明：
1. APP 在运行时执行了 DNS TXT 查询（"failed to get dns txt result" = 查询失败）
2. "游戏盾"是本地代理组件，在 127.0.0.1:31026 和 31818 上监听
3. Telegram 网络层（tgnet）连接到本地代理，代理负责把流量转发到 C2

## 8.6 tcpdump 网络抓包

```bash
# 在手机上用 tcpdump 抓包（需要 root）
adb shell "su -c 'tcpdump -i any -nn -s 0 -c 200 port 53 or port 10500 or port 443'" > /tmp/tcpdump.log 2>&1 &
# 在手机屏幕上操作 APP（点击、输入）
adb shell input tap 540 1200
adb shell input text "13800138000"
sleep 10
# 查看抓包结果
cat /tmp/tcpdump.log | head -40
```

发现 APP 向 `223.5.5.5:53`（阿里 AliDNS）发起 DNS 查询——这正是 187689 的 dnsGroup 2 的 DNS server。

---

# 9. 聚类分析与跨家族关联

## 9.1 聚类方法

按照以下维度对 36 个 APK 进行聚类：

1. **共享包名/代码框架**：是否基于同一个开源项目改造
2. **共享 C2 基础设施**：是否使用相同的域名、IP、DNS server
3. **共享加密密钥**：是否使用相同的加密 key
4. **共享构建变体**：RustDesk 的 .so 构建路径

## 9.2 7 个聚类结果

| 聚类 | 数量 | 共同特征 |
|------|------|---------|
| DNS TXT C2 家族 | 14 | StringFog+AES+XXTEA 4层加密, 共享7个密钥, DNS TXT 分发C2 |
| RustDesk 远程控制 | 11 | librustdesk.so, Flutter壳, 端口10500, Telegram Bot通知 |
| Telegram 改造 IM | 4 | libtmessages, m12345.com, nebulachat3 Firebase |
| WildfireChat 克隆 | 2 | cn.wildfire.chat.kit, TURN 137.220.185.51 |
| 贷款诈骗 | 2 | 伪装贷款APP, REQUEST_INSTALL_PACKAGES |
| 仿冒办公 IM | 1 | IN办公, 电话拦截, io.codenow.cn websocket C2 |
| 非恶意 | 1 | FFmpeg/ExoPlayer 多媒体应用 |

## 9.3 跨家族关联（关键发现）

通过对比不同聚类的 IOC，发现跨家族的关联：

| 关联点 | 家族 A | 家族 B | 说明 |
|--------|--------|--------|------|
| `bjz.com` | DNS TXT C2 (DF165C93) | Telegram IM (187693) | 两个不同家族的 APK 使用了同一个域名 |
| `bw677.com` | DNS TXT C2 (183651 DoT) | Telegram IM (187693) | 183651 的 DoT 域名 = 187693 的 C2 域名 |
| `192.168.1.4:20000` | DNS TXT C2 (DF165C93 开发IP) | Telegram IM (187693 硬编码IP) | 同一个开发环境 IP |
| Telegram 开源 | DNS TXT C2 家族 | Telegram IM | 都基于 Telegram 客户端改造 |
| `com.carriez.flutter_hbb` | RustDesk | Telegram IM (187674) | RustDesk 衍生代码 |

**结论**: DNS TXT C2 家族和 Telegram 改造 IM 很可能是**同一攻击组织的不同工具线**。RustDesk 家族可能是第三个工具线。

---

# 10. 工具源码清单

| 工具 | 源码路径 | 用途 |
|------|---------|------|
| DNS TXT C2 解密工具 | `/home/ninini/Agents/APK-Research/dns_txt_c2_decryptor.py` | 自动提取+解密 NetworkConstant.k + DNS TXT 查询 + C2 IP 提取 |
| Frida 脱壳脚本 | `/home/ninini/Agents/APK-Research/dump_dex.py` | 使用 frida-dexdump 从内存中提取加密的 dex |
| Frida native hook 脚本 | `/home/ninini/Agents/APK-Research/hook_native3.py` | hook libc 的 connect/getaddrinfo/openat 等函数，抓取运行时行为 |
| RustDesk 分析脚本 | `/home/ninini/Agents/AI-APK/samples/0401/analyze_rustdesk.py` | 从 librustdesk.so 提取 C2 域名、URL、构建变体 |
| 通用 APK 扫描脚本 | `/home/ninini/Agents/AI-APK/samples/0401/scan_malware.py` | 批量扫描 APK 的恶意软件特征 |
| 7 APK 分析脚本 | `/home/ninini/Agents/Hermes-Agent/analyze_7_apks*.py` | 子 agent 写的 7 个未分类 APK 分析脚本 |
| AgenticAPKFlow | `/home/ninini/Agents/APK-Research/AgenticAPKFlow/` | LLM 驱动的多 Agent APK 分析平台 (Docker) |
| Hermes Skill | `~/.hermes/skills/research/android-apk-malware-analysis/SKILL.md` | Hermes Agent 技能文件 v2.0.0 |

---

# 11. 所有报告文件清单

| 报告 | 路径 | 内容 |
|------|------|------|
| **详细分析+聚类报告** | `/home/ninini/Agents/APK-Research/DETAILED_ANALYSIS_AND_CLUSTERING.md` | 36 个 APK 逐个详细分析 + 7 个聚类 + 跨家族关联 |
| **最终综合报告** | `/home/ninini/Agents/APK-Research/FINAL_COMPREHENSIVE_REPORT.md` | 分类总览 + IOC + 处置建议 |
| **DF165C93 深度报告** | `/home/ninini/Agents/APK-Research/DF165C93_malware_analysis.md` | DF165C93 的完整逆向分析 |
| **批量分析报告** | `/home/ninini/Agents/APK-Research/0401_batch_analysis.md` | 13 个 APK 的批量解密结果 |
| **加密样本报告** | `/home/ninini/Agents/APK-Research/encrypted_samples_analysis.md` | 3 个加密 APK 的脱壳分析 |
| **脱壳 dex 目录** | `/home/ninini/Agents/APK-Research/dumped_dex/187689/` | 33 个脱壳后的 dex 文件 |
| **脱壳 dex 目录** | `/home/ninini/Agents/APK-Research/dumped_dex/187702/` | 32 个脱壳后的 dex 文件 |
| **运行时事件** | `/home/ninini/Agents/APK-Research/dumped_dex/187689_runtime_events.json` | Frida hook 抓取的 256 个运行时事件 |

---

# 12. 最终统计

| 指标 | 数量 |
|------|------|
| 总 APK | 36 |
| 恶意 APK | 35 |
| 非恶意 APK | 1 |
| 聚类数 | 7 |
| 子聚类数 | 14 |
| C2 IP 地址 (唯一) | 130+ |
| C2 域名 (唯一) | 25+ |
| DNS TXT 分发域名 | 12 |
| 加密层 (最深) | 4 层 |
| 脱壳成功 APK | 2 (187689: 33 dex, 187702: 32 dex) |
| 运行时 hook APK | 1 (187689: 256 事件) |
| 共享加密密钥 | 7 个 |
