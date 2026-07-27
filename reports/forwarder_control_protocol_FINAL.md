# Forwarder Control 协议 — 完整逆向（离线可复现）

**逆向来源**: libgojni.so (dh139/718xssp20), Ghidra 12.1.2 反编译
**函数**: `FetchForwarderFixedTuple` @0x53f900, `signForwarderHelloMAC` @0x53f2a0,
`randomForwarderNonce` @0x53f7c0, `hmacSHA256Hex` @0x53f610,
`verifyForwarderResponseMAC` @0x53f3c0, `tryForwarderControlEndpoints` @0x541390
**源码路径**: D:/im_sdk2/sdk_app2/sdk/forwarder_control.go

---

## 核心结论（推翻此前所有假设）

获取 app_line_ips 的 forwarder control **是纯标准 TLS + 明文 JSON**，与之前以为的
PSK/DEADBEEF/utls/MTProto/auth_key **全部无关**。之前 exdyfb 直连被 302，唯一原因是
**没有设置 ALPN = `cursor-control-v1`**。服务端只对协商到这个 ALPN 的连接说话，否则当
普通 HTTPS 打发去百度（302 诱饵）。

- `cursor-control-v1` = **ALPN 协议名**（不是 PSK identity！）
- "empty control psk" 只是那个 HMAC key 字段的开发者命名，不代表用 TLS-PSK

---

## 协议流程

```
1. 普通 TCP 连接到 控制节点 host:port（控制节点从 .dat 解密 / DNS TXT 得到，离线可得）
2. 标准 crypto/tls 握手:
     MinVersion = MaxVersion = 0x0303 (TLS 1.2)
     InsecureSkipVerify = true          （不校验服务端证书）
     ServerName = <伪装 SNI>            （每样本不同, 见配置表, 如 www.bootcdn.cn）
     NextProtos = ["cursor-control-v1"] （ALPN — 关键“敲门”）
3. 握手后校验 conn.ConnectionState().NegotiatedProtocol == "cursor-control-v1"
     否则报 "unexpected alpn %q"（服务端没回这个 ALPN 就说明进错门）
4. 构造 fwdHelloRequest（见下），json.Marshal 后 **追加一个 '\n'(0x0A)**，明文写入 TLS
5. 读 4 字节 **大端** 长度前缀 (io.ReadAtLeast 4)
6. 读 length 字节 body (1..65536)
7. json.Unmarshal(body) → fwdControlResponse（明文 JSON，含 app_line_ips）
8. verifyForwarderResponseMAC 校验响应 MAC（客户端行为，采集时可跳过）
```

**无任何应用层加密。DEADBEEF/obfs/MTProto 是另一条“代理转发”通道，与拿节点无关。**

---

## fwdHelloRequest（请求 JSON）

字段（来自 reflect JSON tag + 反编译）：

```json
{
  "version": 0,
  "type": "hello",
  "nonce": "<nonceHex><nonceTs>",
  "mac": "<hmac hex>",
  "device_uuid": "<uuid>",
  "sdk_version": "<sdk版本, 可能为空>",
  "timestamp_unix": <当前 Unix 秒>
}
```

- `nonceHex` = hex(crypto/rand 16 字节) → 32 个小写 hex 字符
- `nonceTs`  = strconv.FormatInt(time.Now().UnixNano(), 36)  （base36）
- JSON `nonce` 字段 = nonceHex **直接拼接** nonceTs
- 服务端从 nonce 前 32 字符切出 nonceHex，其余为 nonceTs（与 MAC 字段对应）

---

## MAC 算法（signForwarderHelloMAC，已确认）

```
msg = strings.Join([
  "v1",          // 硬编码
  "hello",       // 硬编码
  nonceHex,      // nonce 前 32 hex
  deviceUUID,
  sdkVersion,    // 配置的 sdk_version（可能为空字符串）
  versionStr,    // version==0 时为 ""，否则 FormatUint(version,10)
  tsStr,         // FormatInt(timestamp_unix, 10)
  nonceTs,       // base36(nanotime)
], "|")

mac = hex( HMAC-SHA256(KEY, msg) )   // 小写 hex，标准 HMAC
```

**KEY = ？** —— 唯一未 100% 定死的点。强证据指向 **AES_key**（每样本 RSA-bootstrap 解出、
服务端已知、可校验）。备选：某个独立 control psk 字段。采集脚本用 AES_key 优先，失败再试其它。

响应 MAC 校验：`HMAC-SHA256(KEY, json.Marshal(resp 但把 mac 字段置空))`，常量时间比较。

---

## fwdControlResponse（响应 JSON）

```json
{
  "nonce": "...",
  "mac": "...",
  "fixed": {...},
  "fixed_set": {...},
  "app_line_ips": ["1.2.3.4", ...],   ← 目标！
  "app_line_port": 30139
}
```

出错时 type/字段含 "error"/"notmodified"(notmodified)/"fixeduptple" 等，配合
"control error %s: %s (retry_after=%d)"。

---

## 离线复现所需输入（全部无需手机）

| 输入 | 来源 | 离线? |
|------|------|-------|
| 控制节点 host:port | .dat 解密 (nodesA) / DNS TXT | ✅ 已实现 |
| AES_key (=HMAC KEY 候选) | RSA 解密 bootstrap | ✅ 已实现 |
| 伪装 SNI | bootstrap / 配置表 | ✅ |
| device_uuid | **客户端自选**（服务端从 identity 重算，任意值即可） | ✅ |
| ALPN | 固定 "cursor-control-v1" | ✅ |
| sdk_version | 配置（多为空） | ✅ |

→ **对全部 508 个样本可写成确定性批量脚本，一台设备都不用。**
唯一需一次性确认的是 KEY 是否为 AES_key（连一个存活控制节点试一次即可判定）。
