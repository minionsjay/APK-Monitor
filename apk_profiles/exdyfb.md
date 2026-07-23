# APK 分析报告: exdyfb

## 基本信息

| 项目 | 值 |
|------|-----|
| APK ID | exdyfb |
| 来源 | 福建管局下发 |
| APK 路径 | /mnt/e/Work/App-analyze/Apks/0722福建下发/7.16exdyfb.apk |
| 下载链接 |  |
| 包名 | bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns |
| 首次发现 | 2026-07-16 |
| 检测分数 | 160/100 |

## SDK 配置

| 项目 | 值 |
|------|-----|
| app_name | dh151 |
| app_domain | *.qianchixt.com |
| app_domain_port | 30151 |
| AES-key | qtOtoF14cKxTjrTo0m8iyHfEI18RK7Yb |
| SNI | www.bootcdn.cn |
| TLS 指纹 | 360Browser |
| SDK 版本 | 4.0.1 |
| local_port | 60151 |

## 加固信息

| 项目 | 值 |
|------|-----|
| 加固壳 | 否 |
| 加固方式 | 无 |
| 加密 dex 路径 | 无 |
| 壳库名 | libbxbHMsUfqiNvARG.so |
| tgnet 库名 | libSgzqvwvAiApn.so |

## .dat 文件

| 项目 | 值 |
|------|-----|
| .dat URL | https://643545e85b5d966b.oss-accelerate.aliyuncs.com/24b015f6b2b5dd17.dat |
| .dat 解密结果 | 无 |
| DNS TXT | 43.248.2.74:30151 |
| PSK | pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7 |

## 控制面节点

- 106.53.12.54:30151
- 193.112.206.154:30151
- 8.138.41.144:30151

## 代理节点 (18 个)

- 139.199.11.70 (腾讯云)
- 159.75.81.201 (腾讯云)
- 103.45.129.234 (未知)
- 8.134.185.37 (阿里云)
- 43.139.215.71 (腾讯云)
- 103.120.90.46 (未知)
- 8.134.147.207 (阿里云)
- 8.134.135.186 (阿里云)
- 175.178.83.21 (腾讯云)
- 8.134.95.207 (阿里云)
- 43.136.98.107 (腾讯云)
- 123.207.63.125 (腾讯云)
- 8.134.209.215 (阿里云)
- 159.75.132.144 (腾讯云)
- 8.138.80.131 (阿里云)
- 8.138.97.66 (阿里云)
- 8.138.44.106 (阿里云)
- 8.134.69.174 (阿里云)

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
