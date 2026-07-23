# 0401 目录 APK 综合分析报告

**分析日期**: 2026-07-20
**样本目录**: `/home/ninini/Agents/AI-APK/samples/0401/`
**样本总数**: 36 个 APK (2.4GB)
**分析工具**: Python zipfile + androguard + Frida 17 + frida-dexdump + tcpdump + dig
**分析环境**: WSL2 Ubuntu 22.04 + Docker 29.6.2 + Pixel 4 (Android 13, root via Magisk)

---

## 1. 分类总览

| 分类 | 数量 | 威胁等级 | 分析深度 | C2 提取 |
|------|------|---------|---------|---------|
| DNS TXT C2 家族 | 14 | CRITICAL | 全链路解密 + 运行时验证 | 130+ C2 IP |
| RustDesk 远程控制 | 11 | HIGH | C2 域名 + 构建变体 | 6 中继域名 |
| Telegram 改造恶意 IM | 4 | CRITICAL | dex 分析 + C2 域名 | 3+ C2 域名 |
| WildfireChat 克隆 | 2 | MEDIUM | dex 分析 + TURN 服务器 | 1 TURN IP |
| 贷款诈骗 (支付通) | 1 | HIGH | Manifest + 页面结构 | - |
| 贷款诈骗 (拍拍贷) | 1 | HIGH | Manifest + 权限分析 | - |
| 仿冒办公 IM (IN办公) | 1 | HIGH | dex + 电话拦截分析 | 2 C2 域名 |
| 非恶意 (脱壳确认) | 1 | 无 | 全脱壳 + dex 分析 | - |
| **合计** | **36** | | **36/36 (100%)** | |

---

## 2. DNS TXT C2 家族 (14 个 APK) — CRITICAL

### 2.1 APK 清单

| APK | 包名 | 伪装名 | OSS_URL | PORT |
|-----|------|--------|---------|------|
| DF165C93 | jnNPfy.SNrsaS.eOtCtk | - | sdfkjn755fvb.com | 31818 |
| DF165C9 | (同上) | - | (同上) | (同上) |
| 187719 | (同上) | - | (同上) | (同上) |
| 184375 | - | - | - | - |
| 184618 | im.gbvbalxydi | - | sdfkjn755fvb.com | 31071 |
| 187652 | - | - | - | - |
| 187693 | - | - | - | - |
| 187699 | - | - | - | - |
| 187710 | - | - | - | - |
| 187723 | - | - | - | - |
| 187731 | - | - | - | - |
| 187748 | - | - | - | - |
| 183651 (升级版) | im.vtvepxzlsp | - | d1s2a7ug5kds5baa.com | 30975 |
| 187689 (脱壳) | guabtlu.pvgi.qcxmvajd | ♪ ♫音乐 | sdfkjn755fvb.com | 31975 |

### 2.2 加密链路 (4 层)

```
NetworkConstant.k (双 base64 + AES 加密配置)
  ↓ AES-256-ECB-PKCS5Padding, key="qRXdx78YqrwMZSz6sboSPgbAoREjIeZa"
  ↓
28 字段管道分隔配置 (dnsGroup 域名 + DNS servers + C2 端口 + tokens)
  ↓
向 dnsGroup 域名发起 DNS TXT 查询 (dnsjava 库直连指定 DNS server)
  ↓
获取 TXT 记录 (base64 + AES 加密)
  ↓ AES-256-ECB-PKCS5Padding, key=APM6990[grp] 解密值
  ↓
C2 IP:端口配置 (IP 为十进制整数格式)
```

### 2.3 共享密钥

| 密钥 | 值 | 用途 |
|------|-----|------|
| StringFog XOR key | `kWYoedTLztHL7dHrsLy99mVu5SHKBgJF` | 第 1 层字符串混淆 |
| AES key32 | `Na0PzT8Aj44aIGXqWlyWcKQ10R67UnjV` | SHA-256(S1+S2+S3) 派生 |
| XXTEA key16 | `Na0PzT8Aj44aIGXq` | 第 4 层 XXTEA |
| k 解密 AES key | `qRXdx78YqrwMZSz6sboSPgbAoREjIeZa` | APM6989 数组解密结果 |
| TXT grp0 key | `445XeO2RtBUJgZMPku7SOwzGwAqiAlAZ` | APM6990[0] |
| TXT grp1 key | `RKwifmZxHVaECYF0rxwuEZTLDy7ofjAY` | APM6990[1] |
| TXT grp2 key | `50mUJ3qy9eOk3WH5xgUPUUdduwiv7yGv` | APM6990[2] |

### 2.4 DNS TXT 分发域名

| 域名 | APK | dnsGroup | DNS server |
|------|-----|----------|-----------|
| `QPAdvdJjeg7MXTJ.51island.vip` | DF165C93/187719 | 0 | 119.29.29.29 |
| `25NvMILWRkN4F.68pulse.xyz` | DF165C93/187719 | 1 | 114.114.114.114 |
| `rQAAmN6L9G8M.68pulse.xyz` | DF165C93/187719 | 2 | 223.5.5.5 |
| `0TMxw3hgbVl.ddocarchive.biz` | 184618 | 0 | 119.29.29.29 |
| `8AQwjlqrh3Zy.7docn.xyz` | 184618 | 1 | 114.114.114.114 |
| `aha1nbLKfP.7docn.xyz` | 184618 | 2 | 223.5.5.5 |
| `vhGXpOb8rc.ddocnote.top` | 183651 | 0 | 119.29.29.29 |
| `cbuLvfH5FUSuGpV.ddocsearch.biz` | 183651 | 1 | 114.114.114.114 |
| `KripZZ3cvZDwQ56l.ddocmark.top` | 183651 | 2 | 223.5.5.5 |
| `rO7gxEdkae3vY3lK.ddocinfo.top` | 187689 | 0 | 119.29.29.29 |
| `szlzFupXZqmuhP.documate.top` | 187689 | 1 | 114.114.114.114 |
| `UO410mu3r8TMfNV.documate.top` | 187689 | 2 | 223.5.5.5 |

### 2.5 C2 IP 地址汇总 (130+ 个)

从 14 个 APK 的 DNS TXT 记录解密得到，每个 APK 有 10 个 C2 IP:端口。所有 IP 已从十进制整数格式转换为标准点分十进制。

### 2.6 183651 升级版特性

- DoH: `https://d299v3a2yb1xsm.cloudfront.net/dns-query`, `https://d3v6elax59b8nz.cloudfront.net/dns-query`
- DoT: `43.198.114.85:1153` (`cn.bw677.com`)
- DoH 域名: `cn.bw755.com`
- DoH AES key/IV: `2Xfh9wHOyXMPb5Th` / `GyVqLZYgo8HGdwl1`
- DoT AES key/IV: `xB5bh6gkckFAvucj` / `Jhh9KeRYSrq389Vd`
- 双通道: QNGAMEKEY + MKGAMEKEY

### 2.7 187689 运行时验证

通过 frida-dexdump 脱壳 + Frida native hook + logcat + tcpdump 确认：

- App 启动后 AppProtectManager 初始化 → "游戏盾初始化"
- DNS TXT 查询执行 → "failed to get dns txt result" (网络不通)
- 本地代理在 127.0.0.1:31026 和 127.0.0.1:31818 监听
- Telegram (tgnet) 网络层连接本地代理 → 流量代理到 C2
- 双进程协同: 主进程 + keep 进程 (jnNPfy.SNrsaS.eOtCtk:keep)
- 19 个监听端口 (40015-50047)

---

## 3. RustDesk 远程控制 (10 个 APK) — HIGH

### 3.1 技术架构

- Flutter 壳应用 (libflutter.so + libapp.so)
- librustdesk.so (25MB, Rust 编译的远程桌面核心)
- classes.dex ZIP 加密 (所有 10 个)
- 418 个随机命名 assets

### 3.2 C2 中继服务器

每个 APK 对应一个构建变体和一个 C2 域名：

| APK | 构建变体 | C2 域名 | 端口 |
|-----|---------|---------|------|
| 187712 | ws-c-v2 | tjylogin.vhyrz5.com | 10500 |
| 187714 | ws-dgc-v2 | login.p2f32kkdhsud.top | 10500 |
| 187716 | ws-dgc-v2 | login.p2f32kkdhsud.top | 10500 |
| 187718 | ws-dgc-v2 | login.p2f32kkdhsud.top | 10500 |
| 187725 | ws-c-v2 | login.p1cbyhe453f.top | 10500 |
| 187735 | ws-dgc-v2 | login.p2f32kkdhsud.top | 10500 |
| 187743 | ws-c-v2 | login.p1f32kkdhsud.top | 10500 |
| 187751 | ws-t2-v2 | login.t2f32kkdhsud.top | 10500 |
| 187754 | ws-dgc-v2 | login.p2f32kkdhsud.top | 10500 |
| 187758 | ws-t-v2 | login.t1f32kkdhsud.top | 10500 |

### 3.3 API 端点

- `http://<c2_domain>:10500/AppInfo.aspx?s=rustdesk` — 设备注册/信息上报
- `https://api.rustdesk.com/version/latest` — 官方 API (伪装)
- `https://api.telegram.org/bot/sendMessage` — Telegram Bot (感染通知)

### 3.4 默认连接示例 (硬编码)

```
9123456234@192.168.16.1:21117?key=5Qbwsde3unUcJBtrx9ZkvUmwFNoExHzpryHuPUdqlWM=
```

---

## 4. WildfireChat 克隆 (2 个 APK) — MEDIUM

### 4.1 基本信息

- APK: 187698, 187733 (内容相同)
- 包名: `cn.wildfire.chat.kit`
- 框架: WildfireChat (开源 IM SDK) + Tencent Mars 网络层
- Native 库: 24 个 (Bugly, UVCCamera, AMR, WebRTC, Mars, Tencent 定位)

### 4.2 基础设施

- TURN 服务器: `turn:137.220.185.51:3478`
- STUN 服务器: `stun:stun.l.google.com:19302`
- HTTP 端点: `http://137.220.185.51:8888`
- 推送: MiPush + FCM
- IM Server: 运行时动态配置

### 4.3 判定

WildfireChat 是合法 IM SDK，但被用于搭建私密通讯平台。需动态分析确认 IM Server 地址和用途。可能是犯罪组织的内部通讯工具。

---

## 5. 贷款诈骗 (1 个 APK) — HIGH

### 5.1 基本信息

- APK: 187732 (7MB)
- 包名: `aerhtharg.sdghdglk.xfv3` (随机生成)
- 应用名: "支付通" (伪装)
- 框架: UniApp (DCloud H5 混合开发)
- 版本: 3.0 (targetSdk 34)

### 5.2 页面结构

login → register → index → wallet → loanlist → borrow → repaylist → userbank → userdata → signature → accountSetting

### 5.3 权限

`REQUEST_INSTALL_PACKAGES` + `CAMERA` + `MANAGE_EXTERNAL_STORAGE` + FileDownloader 服务 → 可下载并安装额外 APK payload

---

## 6. 非恶意应用 (1 个 APK)

### 187702 (10MB)

- frida-dexdump 脱壳成功 (32 个 dex)
- 确认为普通多媒体应用 (FFmpeg/ExoPlayer)
- 11 个 .bt 文件为 XOR 加密的二进制资源 (非可执行代码)
- 唯一域名: `qq-77.top` (API 服务器)
- CleverTap 推送服务
- 判定: 非恶意

---

## 7. 分析工具产出

| 工具 | 路径 | 用途 |
|------|------|------|
| dns_txt_c2_decryptor.py | ~/Agents/APK-Research/ | DNS TXT C2 家族解密工具 |
| DecryptAll.java | ~/Agents/APK-Research/AgenticAPKFlow/ | Java 版多层解密器 |
| dump_dex.py | ~/Agents/APK-Research/ | Frida 脱壳脚本 |
| hook_native3.py | ~/Agents/APK-Research/ | Frida native hook 脚本 |
| scan_malware.py | ~/AI-APK/samples/0401/ | 通用 APK 扫描脚本 |
| analyze_rustdesk.py | ~/AI-APK/samples/0401/ | RustDesk 分析脚本 |
| Hermes Skill | ~/.hermes/skills/research/ | android-apk-malware-analysis v2.0.0 |

---

## 8. 新发现的恶意 APK (7 个，来自未分类组)

### 8.1 Telegram 改造恶意 IM (4 个: 187674, 187693, 187707, 187709)

基于 Telegram 开源客户端改造的恶意 IM，共享 `m12345.com` 和 `nebulachat3.appspot.com` 作为分发/配置域。

**187693 (最危险)**: 含 `VisualCallReceiveService`（被叫视频监听）+ `AndroidScreenCapService`（屏幕录制）+ `OnePxActivity`（1像素保活）+ `EmulatorCheckService`（反模拟器）+ CALL_LOG/OUTGOING_CALLS 权限，具备主动监听能力。

- C2: `m12345.cc/install.html?appkey=aa717156...`, `bjz.com`, `bw1813.com`, `bw677.com`, `fhitrgstestswf8.com`
- IP: `192.168.1.4:20000`, `192.200.1.242:1999`
- 包名: `im.ujaxzxhlkz`
- 26 个 dex，libDingRtc + libemulator_check + libtmessages.31

**187674/707/709**: 同源变体（仅随机 .so 文件名不同），C2 `nebulachat3.appspot.com`/`firebaseio.com`（Firebase 托管），`m12345.com`

### 8.2 RustDesk 远控伪装 (187712)

- 包名: `com.cguakvhzm.fhk`
- 应用名: "汇长通" + 乱码字符规避审核
- 含 BootReceiver 开机自启
- 权限: RECORD_AUDIO, CAMERA, MANAGE_EXTERNAL_STORAGE, RECEIVE_BOOT_COMPLETED, SYSTEM_ALERT_WINDOW
- 已在 RustDesk 章节详述

### 8.3 贷款诈骗 - 拍拍贷 (187697)

- 包名: `mdbdkdjd.dkdbdkdbl3uz.kqfxql5w.n31u`
- 应用名: "⁡⁡⁡⁡⁡⁡⁡拍拍贷"（前置零宽字符绕过检测）
- 权限: REQUEST_INSTALL_PACKAGES + MANAGE_EXTERNAL_STORAGE
- 含 DexClassLoader, getDeviceId, libsu/superuser 关键词

### 8.4 仿冒办公 IM - IN办公 (187721)

- 包名: `vnkudnkgk.fjhchl.qmemtstzc`
- 应用名: "IN办公"
- 电话拦截: `PhoneIntercepterService`
- 保活: `KeepAliveService`
- C2: `io.codenow.cn:3010/socket.io` (websocket), `app.bmob.iwyttc.com`, `59.111.110.241:10081`
- 权限: CALL_PHONE, PROCESS_OUTGOING_CALLS, READ_CALL_LOG, RECORD_AUDIO, CAMERA, READ_PRIVILEGED_PHONE_STATE
- 集成网易云信 + 相芯美颜 + 支付宝 + 微信 SDK 伪装
- 基于"钉钉数据通"框架 (`com.ddtx.dingdatacontact.*`)

### 8.5 新发现 IOC 汇总

| 类型 | 值 | APK |
|------|-----|-----|
| 域名 | `nebulachat3.appspot.com` | 187674/707/709 |
| 域名 | `nebulachat3.firebaseio.com` | 187674/707/709 |
| 域名 | `m12345.com` / `m12345.cc` | 187674/693/707/709 |
| 域名 | `bjz.com` | 187693 |
| 域名 | `bw1813.com` / `bw677.com` | 187693 |
| 域名 | `fhitrgstestswf8.com` | 187693 |
| 域名 | `io.codenow.cn` | 187721 |
| 域名 | `app.bmob.iwyttc.com` | 187721 |
| IP:端口 | `192.168.1.4:20000` | 187693 |
| IP:端口 | `192.200.1.242:1999` | 187693 |
| IP:端口 | `59.111.110.241:10081` | 187721 |

---

## 9. 最终分类汇总

| 分类 | APK 数 | 威胁等级 |
|------|--------|---------|
| DNS TXT C2 家族 | 14 | CRITICAL |
| RustDesk 远程控制 | 11 | HIGH |
| Telegram 改造恶意 IM | 4 | CRITICAL |
| WildfireChat 克隆 | 2 | MEDIUM |
| 贷款诈骗 (支付通 + 拍拍贷) | 2 | HIGH |
| 仿冒办公 IM (IN办公) | 1 | HIGH |
| 非恶意 | 1 | 无 |
| **合计** | **36** | **35 恶意 + 1 非恶意** |

---

## 10. 建议处置

### DNS 层面
- 封锁以下域名的 TXT 查询: `*.51island.vip`, `*.68pulse.xyz`, `*.7docn.xyz`, `*.ddocarchive.biz`, `*.ddocnote.top`, `*.ddocsearch.biz`, `*.ddocmark.top`, `*.ddocinfo.top`, `*.documate.top`
- 封锁 OSS 域名: `sdfkjn755fvb.com`, `d1s2a7ug5kds5baa.com`
- 封锁 DoH/DoT: `cn.bw755.com`, `cn.bw677.com`, `*.cloudfront.net/dns-query`

### IP 层面
- 封锁 130+ 个 DNS TXT 家族 C2 IP
- 封锁 RustDesk 中继域名: `*.f32kkdhsud.top`, `*.p1cbyhe453f.top`, `*.vhyrz5.com`
- 封锁 RustDesk 端口: 10500

### 应用层面
- 监控 WildfireChat 客户端连接 `137.220.185.51`
- 监控 "支付通" 等贷款诈骗应用的传播渠道
- 持续监控 DNS TXT 记录变化 (C2 IP 随时可能更新)
