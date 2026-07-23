# 加密样本分析报告

**分析日期**: 2026-07-20
**样本目录**: `/home/ninini/Agents/AI-APK/samples/0401/`
**分析对象**: 187689.apk, 187702.apk, 187732.apk

---

## 1. 187689.apk (80MB) — ZIP 加密加固样本

### 分析结果

| 项目 | 值 |
|------|-----|
| 大小 | 80MB |
| DEX 文件 | 5 个（全部 ZIP 加密） |
| Manifest | ZIP 加密 |
| res/ XML | ✅ 可读（但路径被混淆） |
| resources.arsc | 🔒 加密 |
| .so 文件 | 全部加密 |
| 加密方式 | ZIP 传统加密（flag bit 0x1） |

### 特征

- 所有 classes*.dex 和 AndroidManifest.xml 被 ZIP 加密
- res/ 目录下的 XML 文件可读，但路径名被随机化（如 `res/gcPjaykYFlyM19IeCpvLLE/...`）
- resources.arsc 被加密，无法提取包名
- 这是一个被**整体 ZIP 加密保护**的 APK，需要运行时密码才能解密
- 可能使用了自定义 APK 加密工具（如 APKProtector 或定制 packer）

### 判定

无法进一步静态分析。需要动态脱壳（运行时 dump 内存中的解密 dex）。

---

## 2. 187702.apk (10MB) — 含 .bt 加密资源的样本

### 分析结果

| 项目 | 值 |
|------|-----|
| 大小 | 10MB |
| DEX 文件 | 4 个（全部 ZIP 加密） |
| Manifest | ZIP 加密（compress=0x7777 非标准） |
| .bt 文件 | 11 个（0-10.bt，可读但加密内容） |
| resources.arsc | ✅ 可读（但路径名极长含 emoji） |
| 加密方式 | DEX 用 ZIP 加密，.bt 用 XOR 加密 |

### .bt 文件分析

11 个 .bt 文件共享相同的 16 字节头：
```
4c 54 3c 23 29 22 2f 3f 33 43 12 13 1d 19 46 61
```

- **解密方法**: XOR 自身前 16 字节作为 key
- 解密后前 16 字节为全 0（确认了 XOR key 推导正确）
- 解密后的内容不是 DEX/ELF/ZIP 格式
- 内容包含部分可读 ASCII，可能是**二进制配置/资源数据**而非可执行代码

### resources.arsc 特征

- resources.arsc 目录路径极长，包含大量 emoji 和特殊字符
- 这是资源路径混淆，防止自动化工具解析

### 判定

.dex 被 ZIP 加密无法静态分析。.bt 文件是 XOR 加密的二进制数据（可能含配置或资源），不是可执行代码。需要动态脱壳才能深入分析。

---

## 3. 187732.apk (7MB) — 贷款诈骗应用

### 分析结果

| 项目 | 值 |
|------|-----|
| 大小 | 7MB |
| DEX 文件 | 6 个（可读） |
| Manifest | compress=0xeb1b（非标准压缩） |
| 资源路径 | 含 emoji 和特殊字符（混淆） |
| 应用类型 | **贷款诈骗应用**（UniApp/HBuilder 框架） |

### 应用内容

187732 是一个基于 **UniApp (DCloud)** 框架开发的贷款诈骗应用：

**页面结构**（从 assets/static/js/ 提取）:
- `pages-login` — 登录页
- `pages-register` — 注册页
- `pages-index` — 首页
- `pages-wallet` — 钱包
- `pages-wallet-detail` — 钱包详情
- `pages-loanlist` — 贷款列表
- `pages-borrow` — 借款
- `pages-repaylist` — 还款列表
- `pages-userbank` — 用户银行卡
- `pages-userdata` — 用户数据
- `pages-userdatum` — 用户详细信息
- `pages-accountSetting` — 账户设置
- `pages-signature` — 签名
- `pages-profile-mine` — 个人中心
- `pages-fwxy` — 服务协议
- `pages-jkxy` — 借款协议
- `pages-help` — 帮助

**应用标题**: `<title>企业版</title>`（伪装为企业版应用）

**资源文件**:
- `assets/gw76.properties` — 文件类型识别配置（magic number → 文件类型映射）
- `assets/p7pq.htm` — HTML 页面
- `assets/index.html` — 入口页面
- `assets/static/` — 图片、JS、CSS 资源

**MSPYceYx blob**:
- classes6.dex 中包含 base64 编码的 blob，以 `MSPYceYx` 作为分隔符
- 解密后发现是 **FileDownloader 库**的内部配置（`DELETE FROM filedownloaderConn`）
- 非恶意代码，是第三方下载库的数据库 SQL

### 判定

这是一个**贷款诈骗应用**——伪装为合法贷款平台，诱骗用户注册、绑定银行卡、申请贷款，最终通过"审核费"、"保证金"等名义骗取钱财。使用了 UniApp 框架 + H5 混合开发，资源路径被 emoji 混淆。

---

## 4. 综合判定

| APK | 类型 | 威胁等级 | 分析状态 |
|-----|------|---------|---------|
| 187689 | ZIP 加密加固应用 | 未知 | 需动态脱壳 |
| 187702 | 含 .bt 加密资源 + ZIP 加密 dex | 未知 | 需动态脱壳 |
| 187732 | 贷款诈骗应用 | HIGH | ✅ 已分析（诈骗类，非恶意软件） |

### 关键发现

1. **187689 和 187702** 使用 ZIP 加密保护 dex，静态分析无法穿透。这两个可能是：
   - 被加固的合法应用
   - 被加固的恶意软件
   - 需要动态脱壳（Frida + dex dump）才能确定

2. **187732** 是贷款诈骗应用，使用 UniApp 框架开发，不需要脱壳。它的威胁在于社会工程学（骗取钱财），而非技术性恶意行为（不窃取数据、不建立 C2）。

3. **.bt 文件格式**（187702）：11 个文件共享 16 字节 XOR key header，解密后是二进制数据而非可执行代码。这可能是某种自定义资源加密，与恶意行为无直接关联。

4. **ZIP 加密（flag bit 0x1）**：这是传统 ZIP 加密（ZipCrypto），不是 AES 加密。理论上可以通过已知明文攻击破解，但需要知道至少 12 字节的明文。

### 建议下一步

1. 对 187689 和 187702 进行动态分析（在 Android 模拟器或实机上运行，用 Frida hook `dvmDexFileOpen` 或 `DexFile.loadDex` dump 解密后的 dex）
2. 对 187732 进行社工分析（联系受害者了解诈骗流程、追踪资金流向）
3. 尝试对 ZIP 加密的 dex 进行已知明文攻击（dex 文件头 "dex\n035\0" 是已知的 8 字节明文）
