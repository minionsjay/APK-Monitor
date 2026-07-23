# 批量 APK 分析报告 - 0401 目录

**样本目录**: `/home/ninini/Agents/AI-APK/samples/0401/`
**样本总数**: 36 个 APK (2.4GB)
**分析日期**: 2026-07-20
**恶意软件家族**: 同一家族（重组 Telegram 克隆 + DNS TXT C2 + 多层加密）

---

## 1. 批量扫描结果

| 分类 | 数量 |
|------|------|
| 总 APK | 36 |
| 恶意软件（同家族） | 5 |
| 其他/未知 | 31 |

### 恶意 APK 清单

| # | APK | 大小 | 包名 | 特征 |
|---|-----|------|------|------|
| 1 | 183651.apk | 89MB | `vtvepxzlsp.wtnqhc.eqomzsod` | **升级版**（含 DoH/DoT） |
| 2 | 184618.apk | 88MB | `im.gbvbalxydi` | 标准版 |
| 3 | 187719.apk | 64MB | (同 DF165C93) | 标准版 |
| 4 | DF165C9.apk | 79MB | (同 DF165C93) | 标准版 |
| 5 | DF165C93*.apk | 79MB | `jnNPfy.SNrsaS.eOtCtk` | 已深度分析（见单独报告） |

---

## 2. 解密后的 C2 服务器完整列表

### 2.1 DF165C93 / 187719（相同配置）

**dnsGroup 配置域名**:
| Group | 域名 | DNS Server |
|-------|------|-----------|
| 0 | `QPAdvdJjeg7MXTJ.51island.vip` | 119.29.29.29, 8.8.8.8 |
| 1 | `25NvMILWRkN4F.68pulse.xyz` | 114.114.114.114, 8.8.8.8 |
| 2 | `rQAAmN6L9G8M.68pulse.xyz` | 223.5.5.5, 8.8.8.8 |

**解密后的 C2 服务器**:
| # | IP | 端口 | dnsGroup |
|---|-----|------|----------|
| 1 | 185.241.176.167 | 1851 | 0 |
| 2 | 48.128.84.143 | 2477 | 0 |
| 3 | 66.87.187.62 | 3126 | 0 |
| 4 | 74.39.35.109 | 8977 | 0 |
| 5 | 243.247.128.54 | 2001 | 1 |
| 6 | 49.1.219.177 | 3053 | 1 |
| 7 | 61.89.100.208 | 2386 | 1 |
| 8 | 26.75.70.82 | 1719 | 2 |
| 9 | 248.103.138.7 | 1441 | 2 |
| 10 | 91.144.153.64 | 2269 | 2 |

### 2.2 184618

**dnsGroup 配置域名**:
| Group | 域名 | DNS Server |
|-------|------|-----------|
| 0 | `0TMxw3hgbVl.ddocarchive.biz` | 119.29.29.29, 8.8.8.8 |
| 1 | `8AQwjlqrh3Zy.7docn.xyz` | 114.114.114.114, 8.8.8.8 |
| 2 | `aha1nbLKfP.7docn.xyz` | 223.5.5.5, 8.8.8.8 |

**解密后的 C2 服务器**:
| # | IP | 端口 | dnsGroup |
|---|-----|------|----------|
| 1 | 26.74.191.69 | 2634 | 0 |
| 2 | 47.229.129.40 | 3025 | 0 |
| 3 | 98.230.7.25 | 2380 | 0 |
| 4 | 115.140.10.87 | 8974 | 0 |
| 5 | 243.248.81.188 | 2766 | 1 |
| 6 | 219.61.51.124 | 1766 | 1 |
| 7 | 136.33.245.217 | 2605 | 1 |
| 8 | 26.74.161.137 | 1703 | 2 |
| 9 | 48.30.173.12 | 1797 | 2 |
| 10 | 66.77.51.51 | 1356 | 2 |

### 2.3 183651（升级版，DoH/DoT）

**配置特征**:
- OSS_URL: `d1s2a7ug5kds5baa.com`（不同基础域名）
- PORT: 30975 / 30816（不同端口）
- **DoH 端点**:
  - `https://d299v3a2yb1xsm.cloudfront.net/dns-query`
  - `https://d3v6elax59b8nz.cloudfront.net/dns-query`
  - （使用 CloudFront CDN 隐藏 DoH 流量）
- **DoT 服务器**: `43.198.114.85:1153`（域名 `cn.bw677.com`）
- **DoH 域名**: `cn.bw755.com`
- 加密参数: `DOH_AEC_KEY=2Xfh9wHOyXMPb5Th`, `DOH_AEC_IV=GyVqLZYgo8HGdwl1`
- DoT 加密: `dotKey=xB5bh6gkckFAvucj`, `dotIv=Jhh9KeRYSrq389Vd`
- 使用 `MKGAMEKEY` 和 `QNGAMEKEY` 代替单一 `k` 字段

---

## 3. 所有发现的域名 IOC

### 3.1 DNS TXT 查询域名（C2 配置分发）

| 域名 | APK | dnsGroup |
|------|-----|----------|
| `QPAdvdJjeg7MXTJ.51island.vip` | DF165C93/187719 | 0 |
| `25NvMILWRkN4F.68pulse.xyz` | DF165C93/187719 | 1 |
| `rQAAmN6L9G8M.68pulse.xyz` | DF165C93/187719 | 2 |
| `0TMxw3hgbVl.ddocarchive.biz` | 184618 | 0 |
| `8AQwjlqrh3Zy.7docn.xyz` | 184618 | 1 |
| `aha1nbLKfP.7docn.xyz` | 184618 | 2 |

### 3.2 OSS 文件下载域名（DGA，每日变化）

| 基础域名 | APK |
|----------|-----|
| `sdfkjn755fvb.com` | DF165C93/187719/184618 |
| `d1s2a7ug5kds5baa.com` | 183651 |

### 3.3 DoH/DoT 域名（183651 升级版）

| 域名/IP | 用途 |
|---------|------|
| `cn.bw755.com` | DoH 域名 |
| `cn.bw677.com` | DoT 域名 |
| `43.198.114.85:1153` | DoT 服务器 |
| `d299v3a2yb1xsm.cloudfront.net` | CloudFront DoH |
| `d3v6elax59b8nz.cloudfront.net` | CloudFront DoH |

---

## 4. 所有 C2 IP 地址汇总（20 个唯一 IP）

```
26.74.161.137
26.74.191.69
26.75.70.82
47.229.129.40
48.128.84.143
48.30.173.12
49.1.219.177
61.89.100.208
66.77.51.51
66.87.187.62
74.39.35.109
91.144.153.64
98.230.7.25
115.140.10.87
136.33.245.217
185.241.176.167
219.61.51.124
243.247.128.54
243.248.81.188
248.103.138.7
```

---

## 5. 加密链路（所有 APK 通用）

```
NetworkConstant.k (双 base64 + AES 加密)
   ↓ AES-256-ECB-PKCS5
   ↓ key = APM6989 数组解密拼接（32 字符 base64）
   ↓
28 字段管道分隔配置（含 dnsGroup 域名+DNS server）
   ↓
向 dnsGroup 域名发起 DNS TXT 查询
   ↓
获取 TXT 记录（base64 加密）
   ↓ AES-256-ECB-PKCS5
   ↓ key = APM6990[grp] 数组解密拼接（32 字符 base64）
   ↓
C2 IP:端口配置（IP 为十进制整数格式）
```

**通用密钥**（所有标准版 APK 共享）:
- StringFog key: `kWYoedTLztHL7dHrsLy99mVu5SHKBgJF`
- AES key32: `Na0PzT8Aj44aIGXqWlyWcKQ10R67UnjV`（SHA-256 派生）
- XXTEA key16: `Na0PzT8Aj44aIGXq`（前 16 字节）
- APM6989 解密结果（k 的 AES key）: `qRXdx78YqrwMZSz6sboSPgbAoREjIeZa`

---

## 6. 183651 升级版特征

183651 是该家族的升级版本，新增了多种 DNS 加密通道：

1. **DNS over HTTPS (DoH)**: 通过 CloudFront CDN 中转，规避 DNS 监控
2. **DNS over TLS (DoT)**: 直连 43.198.114.85:1153，加密 DNS 查询
3. **双配置系统**: `MKGAMEKEY` + `QNGAMEKEY` 替代单一 `k`，支持双 C2 通道
4. **不同基础域名**: `d1s2a7ug5kds5baa.com`（vs 标准版的 `sdfkjn755fvb.com`）
5. **不同端口**: 30975/30816（vs 标准版的 31818）

这表明该恶意软件家族在持续演进，逐步采用更隐蔽的 C2 通信方式。

---

## 7. 建议处置

1. **DNS 层面**: 封锁以下域名的 TXT 查询：
   - `*.51island.vip`, `*.68pulse.xyz`, `*.7docn.xyz`, `*.ddocarchive.biz`
   - `sdfkjn755fvb.com`, `d1s2a7ug5kds5baa.com`
   - `cn.bw755.com`, `cn.bw677.com`

2. **IP 层面**: 封锁上述 20 个 C2 IP

3. **DoH/DoT**: 监控对 `*.cloudfront.net/dns-query` 的异常请求，以及到 `43.198.114.85:1153` 的 TLS 连接

4. **持续监控**: 该家族的 TXT 记录可能随时更新，需定期重新查询获取最新 C2
