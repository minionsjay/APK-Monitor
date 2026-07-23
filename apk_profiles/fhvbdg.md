# APK 分析报告: fhvbdg

## 基本信息

| 项目 | 值 |
|------|-----|
| APK ID | fhvbdg |
| 来源 | 福建管局下发 |
| APK 路径 | /mnt/e/Work/App-analyze/Apks/0722福建下发/7.16fhvbdg(1)/7.16fhvbdg.apk |
| 下载链接 |  |
| 包名 | bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns |
| 首次发现 | 2026-07-16 |
| 检测分数 | 160/100 |

## SDK 配置

| 项目 | 值 |
|------|-----|
| app_name | dh052 |
| app_domain | *.hycuigda052.gnzsmn.com |
| app_domain_port | 30052 |
| AES-key | gYCtoT08cKxQjwVh4m2iyUfEI19WG3Yz |
| SNI | bilibili.com |
| TLS 指纹 | 360Browser |
| SDK 版本 | 4.0.1 |
| local_port | 60052 |

## 加固信息

| 项目 | 值 |
|------|-----|
| 加固壳 | 否 |
| 加固方式 | 无 |
| 加密 dex 路径 | 无 |
| 壳库名 | libbxbHMsUfqiNvARG.so |
| tgnet 库名 | libKQhRjfjQTKQS.so |

## .dat 文件

| 项目 | 值 |
|------|-----|
| .dat URL | None |
| .dat 解密结果 | 无 |
| DNS TXT | 43.248.2.74:30052 |
| PSK | 无 |

## 控制面节点

- 129.204.151.112:30052
- 43.138.250.177:30052
- 8.134.177.243:30052

## 代理节点 (4 个)

- 8.134.140.12 (阿里云)
- 1.12.235.203 (腾讯云)
- 103.45.129.234 (未知)
- 103.120.90.51 (未知)

## 协议信息

| 项目 | 值 |
|------|-----|
| 传输层 | uTLS (Hello360_Auto) → obfsConn (DEADBEEF+padding) → MTProto |
| 配置加密 | RSA-PKCS1v15 (2048bit 私钥嵌入 libgojni.so) |
| .dat 加密 | AES-CBC (key=raw AES_KEY, IV=AES_KEY[:16]) + PKCS7 |
| Forwarder Control | 标准 crypto/tls (TLS 1.2, ECDHE_RSA_WITH_AES_128_CBC_SHA) |
| MAC 算法 | HMAC-SHA256 (key=AES_KEY) |
| 代理节点来源 | MTProto 推送 / fwdControlResponse.FixedA-E |
| 控制面节点来源 | .dat 文件 AES-CBC 解密 → nodesA |
