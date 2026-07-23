# 代理节点获取协议分析（最终版）

## 数据流

```
APP 启动
  ↓
1. RSA 解密 NetworkConstant.k → 配置 (app_name, AES_key, PSK, port, SNI)
  ↓
2. 下载 .dat 文件 → AES-CBC 解密 → 控制面节点 (nodesA)
  ↓
3. DNS TXT 查询 → AES-CBC 解密 → DNS 入口节点
  ↓
4. Forwarder Control (DEADBEEF + JSON, 明文)
   → 请求: fwdHelloRequest{A,B,C,D,E} (HMAC-SHA256 签名)
   → 响应: nodesA (控制面节点列表)
   → 不包含代理节点！
  ↓
5. MTProto 连接 (DEADBEEF + obfs + 加密二进制)
   → obfs 层: crypto/rand padding + 帧头 (不加密)
   → MTProto 层: 自定义加密 (非标准 AES-GCM/CBC)
   → 推送: onIpListReceived(int, String[]) → 明文 IP 数组
   → Java: setAppLineIPsJSON(json) → 保存到 sdk_forwarder_fixed.json
  ↓
6. decryptNodeData (节点数据解密)
   → tryPlainJSON (先尝试直接 JSON)
   → base64.DecodeString (base64 解码)
   → normalizeAESKey (SHA256(AES_KEY) → 32 bytes)
   → tryDecryptGCM (AES-256-GCM 解密)
   → tryDecryptCBC (AES-256-CBC + PKCS7 解密)
   → 输出: JSON (app_line_ips)
```

## 关键函数

| 函数 | 地址 | 作用 |
|------|------|------|
| decryptNodeData | 0x53a060 | 解密节点数据 (base64+AES) |
| tryDecryptGCM | 0x53a400 | AES-GCM 解密 |
| tryDecryptCBC | 0x53a5b0 | AES-CBC 解密 |
| normalizeAESKey | 0x53a340 | SHA256(key) → 32 bytes |
| setAppLineIPs | 0x526780 | 设置代理 IP |
| FetchForwarderFixedTuple | 0x53f900 | Forwarder control 请求 |
| obfsConn.writeFrame | 0x544d60 | obfs 帧封装 (不加密) |
| decodeSecretPayloadWithKey | 0x54dca0 | RSA 解密配置 |

## 离线获取代理节点的方案

### 方案 1: 真机 frida hook (推荐)
hook onIpListReceived 或 setAppLineIPsJSON 的参数
一次性获取 IP 列表

### 方案 2: 真机 sdk_forwarder_fixed.json
定期读取缓存文件

### 方案 3: 模拟器 + cron
模拟器运行 APP + 从 sdk_forwarder_fixed.json 读取
但模拟器上 stub 返回硬编码 IP，不是实时的

### 方案 4: MTProto 协议实现 (最难)
需要逆向 MTProto 握手 + 加密
不是标准 Telegram MTProto
需要大量 Ghidra 逆向工作
