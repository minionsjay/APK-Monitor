# APK逆向工程完整分析报告

## 目标APK信息

| 属性 | 值 |
|------|-----|
| 包名 | cii.gjjvikjqhhupaab.aaoknxedxpgnwa |
| app_name | dh139 |
| 端口 | 30139 |
| AES-key | htHtoU17cKxTjwVh1m2iyHfEI39RG1Cw |
| SNI | share.note.youdao.com → www.bootcdn.cn |
| .dat URL | bf6d955b81de7c44.gz.bceos.com |
| APK类型 | WkNAvY (Telegram clone) |
| SDK源码路径 | D:/im_sdk2/sdk_app2/sdk/ |

## 设备信息

| 属性 | 值 |
|------|-----|
| 真机 | Pixel 4 (192.168.1.16:41879, root, A13, Magisk) |
| 模拟器 | 不可用 (x86_64上APK崩溃, Go runtime SIGILL) |
| frida | 绝对不可用 (导致设备重启) |
| ADB | 端口频繁变化 |
| 环境 | WSL2 Ubuntu 22.04, Docker 29.6.2 |

## 工具链

| 工具 | 版本/路径 |
|------|-----------|
| Go | 1.25.0 (/home/ninini/go/bin/go) |
| Ghidra | 12.1.2 (/home/ninini/ghidra_setup/...) |
| radare2 | /home/ninini/radare2/bin/r2 |
| capstone | pip安装, 用于ARM64反汇编 |
| utls | v1.8.2 (github.com/refraction-networking/utls) |
| mitmproxy | 12.2.3 |
| mihomo | clash代理端口7890 |

---

## 一、完整节点获取流程 (已确认95%)

### 阶段1: DNS TXT → 控制面IP

1. APP域名: sdkghug139.cwenku.com (示例)
2. DNS TXT查询: _dns.{app_domain} → base64加密数据
3. AES-CBC解密(key=AES_key, IV=AES_key[:16]) → 控制面IP (如43.248.2.74)
4. 所有子域名(_dns/_auth/_key/_psk/_control/_config)返回相同TXT(通配符DNS)

**证据**: 实际测试确认, 5个.dat文件返回相同3个初始节点

### 阶段2: .dat文件 → 代理节点

1. HTTPS GET {oss_url}/{hash}.dat (80字节)
2. AES-CBC解密(key=AES_key, IV=AES_key[:16]) → JSON {nodesA, nodesB}
3. 得到3个初始代理节点:
   - 8.134.180.186:30139
   - 8.138.152.138:30139
   - 8.148.148.131:30139

**证据**: 所有5个.dat文件返回相同的3个初始节点

### 阶段3: forwarder control → app_line_ips

#### 3.1 control_refresh_addr (APP内存0x40002a2798确认)

- control_refresh_addr = 123.207.40.186:30139
- 这是代理节点之一(sdk_forwarder_fixed.json中的第13个IP)

#### 3.2 FetchForwarderFixedTuple (libgojni.so, kem_decomp.c)

**函数地址**: 0x53f900 (Ghidra地址)

**源码**: D:/im_sdk2/sdk_app2/sdk/forwarder_control.go:130-208

**完整流程** (从Ghidra反编译确认):

```
行529: strings.TrimSpace(param_5/param_6) → control_refresh_addr
行530: if TrimSpace后为空 → fmt_Errorf("empty control psk")
行557: net.SplitHostPort → 解析host:port
行608: strconv.Atoi → 解析端口号
行613: if 端口<1 → fmt_Errorf("bad port in hostport")
行707: net.Dialer.DialContext → TCP连接到control_refresh_addr
行783: runtime.newobject(&tls.Config) → 创建TLS配置
行815: *(config+0x278) = iVar14 → 设置某些字段
行817: *(iVar14 + 0x80) = iVar10 → 设置某些字段
行605: encoding_json.Marshal(fwdHelloRequest) → JSON序列化
行633: uVar12 = len + 1 → JSON长度+1
行637: runtime_growslice → 追加1字节
行643: *(buf+len-1) = 10 → 写入\n(0x0A)
行644: crypto_tls___Conn__Write → 发送JSON+\n! (明文!)
行666: runtime_newobject(&Array_4_uint8) → 4字节(读取响应4B长度前缀)
行722: runtime_makeslice → 创建响应缓冲区
行750: runtime_newobject(&fwdControlResponse) → 创建响应对象
行753: encoding_json_Unmarshal → 反序列化响应JSON
```

**关键确认**:
- FetchForwarderFixedTuple发送**明文JSON+\n** (行644)
- 响应是**4B长度+JSON** (行666)
- **不封装DEADBEEF!**
- 不加密!

#### 3.3 FetchForwarderFixedTuple的JSON请求 (fwdHelloRequest)

```json
{
  "version": 0,
  "type": "hello",
  "nonce": "<hex(16字节随机)> + <FormatInt(nanos, 36)>",
  "mac": "<HMAC-SHA256>",
  "device_uuid": "<94字符hex>",
  "timestamp_unix": <Unix时间戳>
}
```

#### 3.4 MAC计算 (signForwarderHelloMAC, 0x53f2a0)

**8个字段, 分隔符="|"**:

```
MAC = HMAC-SHA256(AES_key, strings.Join([
  [0] "v1",                    // 硬编码
  [1] "hello",                 // 硬编码
  [2] hex(16字节随机),          // 32字符 (不包含FormatInt!)
  [3] device_uuid,             // 94字符hex
  [4] sdk_version,             // 空字符串(SDKVersion从SecretPayload传入)
  [5] version_str,             // 空字符串(version==0时为空)
  [6] timestamp_str,           // FormatInt(timestamp, 10)
  [7] nonce_ts,                // FormatInt(nanotime, 36)
], "|"))
```

**randomForwarderNonce (0x43f7c0)**:
- 生成16字节随机数 (crypto/rand.Read)
- hex编码 → 32字符nonce
- 同时返回nonce_ts = FormatInt(nanotime, 36)

**证据**: Ghidra反编译signForwarderHelloMAC完整确认

#### 3.5 FetchForwarderFixedTuple的TLS配置

- 用标准crypto/tls (不是utls!)
- TLS版本: TLS1.2 (0x303)
- net.Dialer.DialContext → TCP连接
- crypto/tls.Conn.handshakeContext → TLS握手
- crypto/tls.Conn.Write → 发送JSON+\n

**证据**: kem_decomp.c行149(L155: runtime.newobject(&tls.Config)), 行155(handshakeContext), 行177(Write)

#### 3.6 但VPN拦截TCP连接!

- APP用Android VPN API
- VPN拦截所有TCP连接
- FetchForwarderFixedTuple的DialContext(123.207.40.186:30139)被VPN拦截
- 转发到本地代理(127.0.0.1:60139)

**证据**:
- /proc/PID/net/tcp: 127.0.0.1:60139 LISTEN + 3个ESTAB
- 直接连接60139: 明文TCP→EOF, TLS→timeout, HTTP→timeout
- 60139只接受VPN转发的连接!
- 直接连接123.207.40.186:30139 → 302(HTTP重定向)

---

## 二、DEADBEEF帧格式 (从writeFrame反编译确认)

### 2.1 writeFrame函数 (libgojni.so)

**函数地址**: 0x544d60 (Ghidra确认)

**源码**: D:/im_sdk2/sdk_app2/sdk/obfs.go:48-60

**反编译确认的帧格式**:

```
DEADBEEF(4, 小端序=0xefbeadde存储) + sublen(2, 大端序) + payload_len(2, 大端序) + pad(1) + padding(pad&0x3f) + payload(原始TCP数据)
```

**writeFrame流程** (从Ghidra反编译确认):

```
行52: 大端序转换payload_len (encoding/binary)
行102: pad=0 → 设置pad字段为0
行103: crypto/rand.Read(1字节) → 生成随机padding值
行104: bVar4 = 随机字节
行49: bVar4 & 0x3f → padding大小(0-63)
行50: total = pad_size + payload_len + 9
行53: *buf = 0xefbeadde → DEADBEEF magic(小端序!)
行54: buf[4:6] = sublen(大端序, 通常0)
行55: buf[6:8] = payload_len(大端序)
行55: buf[8] = pad值
行56: crypto/rand.Read(padding) → 随机padding
行60: copy(buf[9+pad:], payload) → 复制payload
```

**关键确认**:
- DEADBEEF magic = 0xefbeadde (小端序存储 = DEADBEEF)
- padding是随机的 (crypto/rand.Read)
- payload_len从参数传入
- **writeFrame只做帧封装, 不加密!**
- **payload = 原始TCP数据(不加密!)**

### 2.2 obfsConn.Write (libgojni.so)

**函数地址**: 0x544c80

**源码**: obfs.go:31-45

```
行33: 循环开始
行35: 如果数据>0x40000(256KB) → 截断为0x40000
行38: 调用writeFrame(param_1, param_2, param_3, param_4)
行39: 计算已发送字节数
行40: 如果出错 → 返回
行43: 更新偏移和剩余长度
行45: 返回
```

**关键确认**: obfsConn.Write只分块调用writeFrame, **不加密!**

### 2.3 relayObfs.func1 (libgojni.so)

**函数地址**: 0x549c30

**源码**: D:/im_sdk2/sdk_app2/sdk/proxy.go:345-359

```
行347: makeslice(0x40000) → 分配256KB缓冲区
行348: 循环: (**func)(conn+0x28)(conn, buf, 0x40000) → 从conn读取
行350: 如果读取了数据:
行351: obfsConn.Write(conn, buf, n, 0x40000) → 写入obfsConn!
行352: mutex lock
行354: mutex unlock
行355: defer cleanup
行358: 继续循环
行359: 如果出错 → 返回
```

**关键确认**:
- relayObfs.func1是**中继函数**!
- 从一个连接读取 → 写入obfsConn
- **不加密! 只是中继!**
- 中继的是APP的**所有TCP流量** (不只是forwarder control)

### 2.4 完整数据流

```
APP (FetchForwarderFixedTuple)
  → JSON+\n → crypto/tls.Conn.Write
  → VPN拦截TCP连接
  → 转发到本地代理(127.0.0.1:60139)
  → 本地代理接受连接(onLocalAccept)
  → relayObfs.func1: 从conn读取 → 写入obfsConn
  → obfsConn.Write → writeFrame → DEADBEEF帧封装
  → 通过TLS连接(utls Chrome115_PQ_PSK)发送到代理节点
  → 代理节点
```

**关键结论**:
- DEADBEEF payload = 原始TCP数据 (不加密!)
- TLS加密在底层 (net.Conn是TLS连接)
- MITM解密TLS后看到的是DEADBEEF帧 (明文payload)
- relayObfs中继所有TCP流量 (包括TLS数据、HTTP、MTProto等)

### 2.5 obfsConn的方法列表 (从Go函数名表确认)

```
proxy-system/sdk.(*obfsConn).Write       → writeFrame
proxy-system/sdk.(*obfsConn).writeFrame  → 帧封装
proxy-system/sdk.(*obfsConn).Read       → getPayload
proxy-system/sdk.(*obfsConn).Close
proxy-system/sdk.(*obfsConn).RemoteAddr
proxy-system/sdk.(*obfsConn).SetDeadline
proxy-system/sdk.(*obfsConn).SetReadDeadline
proxy-system/sdk.(*obfsConn).SetWriteDeadline
proxy-system/sdk.randomByte             → 随机字节生成
proxy-system/sdk.loadRuntimePolicy      → 加载运行时策略
proxy-system/sdk.maskMAC                → 掩码MAC
```

### 2.6 obfsConn相关字符串 (从libgojni.so strings确认)

| 字符串 | 地址 | 用途 |
|--------|------|------|
| "obfs: bad magic 0x%08X" | 0xdd555 | DEADBEEF magic检查 |
| "obfs: buf too small (%d < %d)" | 0xe1c88 | obfs缓冲区检查 |
| "obfs: frame too large (%d > %d)" | 0xe312f | 帧大小检查 |
| "sdk.obfsConn" | 0x4b730d | obfs连接对象 |
| "frame_data_stream_0" | 0xdc0f7 | 帧数据流 |
| "frame_data_pad_too_big" | 0xdd9cd | 帧padding检查 |
| "writeFrame" | 0x4b38d5 | 写帧函数 |
| "getPayload" | 0x4b38d5附近 | 获取payload函数 |
| "onLocalAccept" | 0x4b38d5附近 | 本地代理接受连接 |

---

## 三、DEADBEEF帧中的payload类型

### 3.1 1163B消息 = MTProto消息

从MITM数据(mitmmlkem)确认:
- 1163B在所有utls连接中相同 (固定)
- payload前8字节: 8c01b731e516801b → MTProto auth_key_id
- payload字节8-24: c6bfe935fddaccc4cb2d4d23aab4acff → MTProto msg_key
- payload字节24+: encrypted → MTProto加密数据

**结论**: 1163B是Telegram MTProto握手消息, 不是forwarder control的JSON!

### 3.2 APP内存中的DEADBEEF帧

在APP内存(0x4000010b10-0x40000ac5d0)找到10个DEADBEEF帧:

| 地址 | payload_len | 内容 |
|------|-------------|------|
| 0x4000010d20 | 73 | "30139" + "bb75"(48021) + TLS数据(ContentType=0x17) |
| 0x40000ac5d0 | 329 | "127.0.0.1:60139" |
| 0x4000010bb0 | 556 | "http/1.1" + 嵌套DEADBEEF |
| 0x400008fb00 | 988 | 高entropy加密数据 |
| 0x4000074f71 | 5 | "test\n" (测试数据) |

**关键确认**: DEADBEEF帧包含各种TCP数据 (TLS、HTTP、MTProto、测试数据等)

### 3.3 重放测试结果

| 测试 | 发送 | 结果 |
|------|------|------|
| 重放1163+1169B | MTProto握手 | 收到1835B响应 (12个DEADBEEF) |
| 重放1163+1169+395B | 完整MTProto | 收到2041B响应 (13个DEADBEEF) |
| DEADBEEF+明文JSON | 不先认证 | 302 (HTTP重定向) |
| 重放1163+1169→raw JSON | 先认证→JSON | 收到DEADBEEF响应 (105B加密payload) |
| 重放1163+1169→等响应→raw JSON | 先认证→等→JSON | 收到DEADBEEF响应 (133B加密payload) |

**关键发现**:
- 认证(重放1163+1169B)成功!
- 发送raw JSON成功!
- 但响应是MTProto加密的!
- 需要auth_key解密响应!

---

## 四、auth_key分析

### 4.1 auth_key不是TLS MasterSecret

**证据**:
- 前端MasterSecret: 17435个 × SHA1 → 0匹配
- 后端MasterSecret: 550个 → 0匹配
- EKM (各种label): → 0匹配
- sdk_final_complete.txt说"auth_key=master_secret"是**错误的**!

### 4.2 auth_key_id不是SHA1(auth_key)!

**从tgnet.so反编译确认**:

```
getPermanentAuthKeyId (0xdbe49c, 8字节函数):
  0xdbe49c: ldr x0, [x0, #0x170]  → auth_key_id = Datacenter+0x170
  0xdbe4a0: ret
```

**结论**: auth_key_id是Datacenter对象+0x170字段的直接值, 不是SHA1计算!

### 4.3 auth_key的位置

**从tgnet.so反编译确认**:

```
getAuthKey (0xdbd9d4, 312字节函数):
  0xdbd9f4: ldrb w8, [x0, #0x1a0]  → 读取标志
  0xdbd9f8: cbnz w8, #0xdbda50     → 如果非0(有auth_key)跳转
  
  (有auth_key的分支):
  0xdbda50: cbz x20, #0xdbda5c     → 如果不需要auth_key_id跳转
  0xdbda54: ldr x8, [x19, #0x170]  → auth_key_id = Datacenter+0x170
  0xdbda58: str x8, [x20]          → 存到输出参数
  0xdbda5c: ldr x22, [x19, #0x168] → auth_key = Datacenter+0x168 (NativeByteBuffer*)
  0xdbda60: b 0xdbdaf0             → 返回
  
  (没有auth_key的分支):
  0xdbda68: ldp x22, x25, [x19, #0x1a8] → 临时auth_key链表(+0x1a8/+0x1b0)
```

**Datacenter对象结构**:

| 偏移 | 类型 | 用途 |
|------|------|------|
| +0x10 | int32 | DC ID (0-5) |
| +0x168 | pointer | 永久auth_key (NativeByteBuffer*) |
| +0x170 | int64 | auth_key_id (8字节直接值) |
| +0x1a0 | byte | auth_key标志 (0=没有, 非0=有) |
| +0x1a8 | pointer | 临时auth_key链表起始 |
| +0x1b0 | pointer | 临时auth_key链表结束 |

### 4.4 auth_key的来源 (session)

**从tgnet.so反编译(0xdd2914)确认**:

```
0xdd2ab0: bl 0xdbaf70               → 获取session (x0=ConnectionsManager)
0xdd2ab4: cbz x0, #0xdd2ae4         → 如果session为空
0xdd2ab8: mov x20, x0               → x20 = session对象
0xdd2b7c: add x21, x19, #0x210      → x21 = Connection+0x210 (auth_key位置)
0xdd2b80: add x1, x20, #0x20        → x1 = session+0x20 (auth_key数据)
0xdd2b84: mov x0, x21               → 目标 = Connection+0x210
0xdd2b88: bl 0x15cb8c8              → 复制! session+0x20 → Connection+0x210
```

**结论**: auth_key = session+0x20, 从session cache(0xdbaf70)获取

### 4.5 session从ConnectionsManager获取

**从0xdbaf70确认**:

```
0xdbaf8c: ldr x8, [x0, #0x168]  → ConnectionsManager+0x168 (session链表1)
0xdbaf94: ldr x8, [x0, #0x178]  → ConnectionsManager+0x178 (session链表2)
```

**ConnectionsManager对象结构**:

| 偏移 | 类型 | 用途 |
|------|------|------|
| +0x10 | int32 | DataCenter ID |
| +0x168 | pointer | session链表1 (永久) |
| +0x178 | pointer | session链表2 (临时) |
| +0x1b8 | Go字符串 | 某个key |
| +0x1d0 | Go字符串 | 全局密钥 |
| +0x2eb | byte | 随机选择标志 |
| +0x2ec | byte | 另一个标志 |

### 4.6 auth_key搜索结果 (全部失败)

| 搜索方法 | 范围 | 结果 |
|---------|------|------|
| SHA1(MS[:32])[:8] | 前端MasterSecret 17435个 | 0匹配 |
| SHA1(MS[:48])[:8] | 前端MasterSecret 17435个 | 0匹配 |
| SHA1(MS[:32])[:8] | 后端MasterSecret 550个 | 0匹配 |
| EKM(各种label) | 550个连接 | 0匹配 |
| AES-IGE解密 | rw内存203段 | 0匹配 (AES-IGE是错的!) |
| AES-CFB/CTR解密 | rw内存 | 0匹配 (84724个候选) |
| 16B SHA1 | rw内存471段, 1050万候选 | 0匹配 |
| 32B SHA1 | 同上 | 0匹配 |
| 256B SHA1 | 同上 | 0匹配 |
| auth_key_id(大端序) | 所有段1931个 | 0匹配 |
| auth_key_id(小端序) | 所有段1931个 | 0匹配 |
| tgnet.dat暴力 | 所有偏移×SHA1 | 0匹配 |
| Datacenter对象搜索 | rw内存 | 3个候选(误报) |

**结论**: auth_key不在APP任何可访问的内存位置!

### 4.7 auth_key_id在不同会话中不同

- MITM截获的auth_key_id: 8c01b731e516801b (旧会话)
- 当前Datacenter+0x170: 0x200000007072dcd8 (新会话)
- 确认: **每次会话有不同的auth_key!**

### 4.8 Datacenter对象搜索 (误报)

搜索条件: +0x10(DC ID, 0-5) + +0x168(有效指针) + +0x170(非0)

找到3个候选:
- 0x727f46a8: DC ID=0, +0x168=0x7066b648, +0x170=0x200000007072dcd8
- 0x727f46e8: DC ID=0, +0x168=0x7059f2e8, +0x170=0x20000000704b8610
- 0x727f4710: DC ID=0, +0x168=0x65746f67, +0x170=0x20000000704cf2c8

但NativeByteBuffer(0x7066b648)的数据是低entropy(unique=57/256B), 不是密钥!
可能是误报或NativeByteBuffer结构理解不正确。

---

## 五、加密方式分析 (从tgnet.so反编译确认)

### 5.1 encryptKeyWithSecret (0xdd3cd4)

**功能**: SHA256(data + auth_key) → 32字节AES key

```
0xdd3cd4: ands w8, w2, #0xff     → 检查type
0xdd3cd8: b.eq 0xdd3e04          → 如果type==0, 不加密
0xdd3cf8: cmp w8, #2             → 比较type==2
0xdd3d00: add x20, x0, #0x210   → type==2: key=this+0x210 (永久密钥)
0xdd3d08: mov x20, x0           → type!=2: key=this+0x58 (临时密钥)
```

**密钥选择优先级**:
1. x19+0x40 (第一个key)
2. x19+0x58 (临时密钥, type=1)
3. x19+0x210 (永久密钥/auth_key, type=2)
4. ConnectionsManager+0x1d0 (全局密钥)

**key的第17字节特殊标志**:
- 0xdd → mode 2
- 0xee → mode 3

**SHA256计算**:
```
0xdd3d8c: SHA256_init(sp)       → 初始化(不是HMAC! 没有ipad/opad!)
0xdd3d9c: mov w2, #0x20          → 32字节
0xdd3da0: SHA256_update(data, 32)→ 更新data的前32字节
0xdd3d48-0xdd3d50: min(keylen, 16) → 最多16个key字节
0xdd3dac-0xdd3de0: 循环update(key字节, 1字节each)
0xdd3dec: SHA256_final           → 输出32字节hash → 覆盖data前32字节
```

**关键确认**:
- 不是HMAC-SHA256! 只是普通SHA256!
- SHA256 init(0x8c413c)没有用key做ipad/opad
- 只用auth_key的前**16字节**! (min(keylen, 16))
- SHA256输入 = data[:32] + auth_key[:16]

### 5.2 AES key expansion (0x89f158)

```
0xdd3350: bl 0x89f158           → AES key expansion(hash, 0x100=256)
```

- 使用SHA256的hash作为AES-256 key
- 0x100 = 256 = AES key schedule大小

### 5.3 加密函数 0x89f320 = AES-CFB/CTR (不是AES-IGE!)

**从0x89f320反编译确认**:

```
0x89f324: adr x7, #0x89f1e0     → x7 = AES_encrypt函数
0x89f34c: mov x25, x7           → x25 = AES_encrypt

逐字节XOR(不满16字节部分):
0x89f374: ldrb w8, [x21], #1   → 读取输入字节
0x89f378: ldrb w9, [x20, w27]   → 读取IV字节
0x89f388: eor w8, w9, w8        → XOR
0x89f38c: strb w8, [x23], #1    → 输出
0x89f384: and w27, w10, #0xf    → IV指针循环(0-15)

每16字节:
0x89f3a0: add x23, x23, #8      → 对齐
0x89f3b4: blr x25               → AES_encrypt(IV, IV, expanded_key)
0x89f3b8-0x89f3ec: 计数器递增(大端)
```

**加密流程**:
1. AES_encrypt(IV, IV, key) → keystream
2. output = input XOR keystream
3. IV递增(大端计数器)

**关键确认**:
- 这不是标准AES-IGE!
- 这是AES-CFB或AES-CTR模式!
- 之前所有AES-IGE搜索都是**错误的**!

### 5.4 sendRequest (0xdd2e08) 完整加密流程

**函数范围**: 0xdd2e08 - 0xdd3588

```
第一次加密:
  0xdd333c: bl 0xdd3cd4   → encryptKeyWithSecret (SHA256)
  0xdd3350: bl 0x89f158   → AES key expansion
  0xdd3358: add x27, x19, #0x2ac → IV = x19+0x2ac (来自data)
  0xdd3368: ldr q0, [x27]  → 读取IV(16字节)
  0xdd3370: str q0, [x19, #0x3c0] → 复制IV到IV state
  0xdd3304: str q0, [x19, #0x3d0] → 清零IV2(全0!)

第二次加密:
  0xdd3398: bl 0xdd3cd4   → encryptKeyWithSecret (第二次)
  0xdd33a8: bl 0x89f158   → 第二次AES key expansion

分段加密:
  0xdd33d4: bl 0x89f320   → AES-CFB/CTR(64字节, 消息头)
  0xdd3498: bl 0x89f320   → AES-CFB/CTR(1字节)
  0xdd3504: bl 0x89f320   → AES-CFB/CTR(4字节)
  0xdd3554: bl 0x89f320   → AES-CFB/CTR(剩余数据)
  0xdd3560: bl 0xdb2a00   → append结果
```

**IV来源**:
- IV1 = x19+0x2ac (从输入数据拷贝, 第32-48字节)
- IV2 = 全0 (从0xdd3304确认清零)
- IV1来自x25(随机数据, 0x8ae1d8=getrandom)

**关键确认**:
- sendRequest用随机IV → 每次加密结果不同
- 1163B在所有连接中相同 → **不走sendRequest!**
- 1163B是预先生成的MTProto消息

### 5.5 0x8ae1d8 随机数生成

```
0x8ae1d8 → 0x8ae434:
  0x8be0c0: mov w0, #0x116      → syscall号0x116 = getrandom!
  0x8be0d0: bl 0x1636f40        → syscall!
```

**确认**: 使用Linux syscall getrandom → 真随机数

### 5.6 aes_ige_encrypt/decrypt (0x14da56c/0x14da5d8)

```
aes_ige_encrypt (0x14da56c):
  0x14da590: add x2, sp+8        → expanded key在栈上
  0x14da594: mov x0, x3          → key
  0x14da598: mov w1, #0x100      → 256 (AES-256)
  0x14da5a0: bl 0x89f158         → AES key expansion
  0x14da5b8: mov w5, #1          → encrypt=1
  0x14da5bc: bl 0x8ddfd0         → AES-IGE(out, in, len, key, iv, 1)
```

**注意**: aes_ige_encrypt存在但**不被sendRequest调用**!
sendRequest调用的是0x89f320 (AES-CFB/CTR)!

### 5.7 AES-IGE实际实现 (0x8ddfd0, 供参考)

```
加密(encrypt=1):
  0x8de030: ldr q0, [x19]       → 读取IV1(16字节)
  0x8de034: add x25, x19, #0x10  → x25=IV2(16字节)
  0x8de038: str q0, [sp, #0x10]  → 存IV1
  0x8de03c: ldr q0, [x19, #0x10]→ 读取IV2(16字节)
  0x8de040: str q0, [sp]         → 存IV2

  循环(每个16字节):
    0x8de048: ldr q0, [x22], #0x10 → 读取P_i
    0x8de060: eor v0, v1, v0       → P_i XOR IV1
    0x8de068: bl 0x89f1e0          → AES_encrypt(P_i XOR IV1) → C_i
    0x8de078: eor v0, v1, v0       → C_i XOR IV2 → 输出
    0x8de080-0x8de08c: 更新IV1=C_i XOR IV2, IV2=P_i

  这不是标准AES-IGE!
  I1_new = C_i XOR I2_old (不是C_i XOR P_{i-1}!)
  I2_new = P_i
  这是变体AES-IGE!
```

---

## 六、Go字符串格式 (从0x15cb8c8反编译确认)

### 6.1 Go字符串复制函数 (0x15cb8c8)

```
0x15cb8ec: ldrb w8, [x19]    → 目标第一个字节
0x15cb8f0: ldrb w9, [x1]     → 源第一个字节

情况1: 两者bit0=0 (长字符串):
  0x15cb8fc: ldr x8, [x1, #0x10]  → 读取源ptr(offset 0x10)
  0x15cb900: ldr q0, [x1]          → 读取源前16字节
  0x15cb904: str x8, [x19, #0x10] → 存ptr到目标offset 0x10
  0x15cb908: str q0, [x19]        → 存前16字节
  → 复制24字节

情况2: 目标bit0=1 (短字符串→长字符串):
  0x15cb910: ldp x11, x10, [x1, #8]  → x11=[src+8], x10=[src+0x10]
  0x15cb914: tst w9, #1               → 测试源bit0
  0x15cb918: lsr x9, x9, #1          → 长度=byte>>1
  0x15cb920: csel x20, x9, x11, eq   → bit0=0: len=byte>>1; bit0=1: len=[src+8]
  0x15cb924: csinc x21, x10, x1, ne  → bit0=0: data=src+1(内联); bit0=1: data=x10(ptr)
```

### 6.2 Go字符串格式

| bit0 | 类型 | 长度 | 数据位置 |
|------|------|------|---------|
| 0 | 短字符串 | byte>>1 (最大63) | offset 1 (内联) |
| 1 | 长字符串 | offset 8 | offset 0x10 (ptr) |

**Go字符串结构**: 24字节
- offset 0: 第一个字节(长度/标志)
- offset 1-15: 内联数据(最多15字节)
- offset 0x10: 数据指针(长字符串)

---

## 七、SecretPayload

### 7.1 SecretPayload结构 (从libgojni.so strings确认)

```
SecretPayload {
    PrivateKeyPEM      (json:"private_key_pem")
    SDKVersion         (json:"sdk_version,omitempty")
    AppLineIPs         (json:"app_line_ips,omitempty")
    AppLineEndpoints   (json:"app_line_endpoints,omitempty")
    AppLinePort        (json:"app_line_port,omitempty")
}
```

**关键**: SecretPayload包含AppLineIPs字段!

### 7.2 RSA私钥

- RSA-2048私钥在APP内存0x4000172705找到
- 1678字节, 以"-----BEGIN RSA PRIVATE KEY-----"开头
- 通过EmbeddedPrivateKeyB64编译时嵌入(ldflags)
- 用于DecodeSecretPayload

### 7.3 SecretPayload相关字符串

| 字符串 | 用途 |
|--------|------|
| "private_key_pem is empty in sdk config file" | 配置不含私钥 |
| "prepare_control_plane_failed_use_domain" | 控制面失败用域名 |
| "control_refresh_addr" | 控制面刷新地址 |
| "no prepare network probe address con..." | 网络探测地址 |
| "forwarderControlPSK" | forwarder control PSK |
| "cursor-control-v1" | PSK identity |
| "empty control psk" | PSK为空报错 |
| "bad port in hostport" | 端口无效报错 |
| "control error %s: %s" | 控制面错误 |

---

## 八、APK配置总览

| APK | app_name | 端口 | AES-key | SNI | .dat URL | 包名 |
|-----|---------|------|---------|-----|---------|------|
| fhvbdg | dh052 | 30052 | gYCtoT08cKxQjwVh4m2iyUfEI19WG3Yz | bilibili.com | N/A | ykw.pxdxtfpmxbl.xdkjurlpwdfwgtwc |
| exdyfb | dh151 | 30151 | qtOtoF14cKxTjrTo0m8iyHfEI18RK7Yb | www.bootcdn.cn | 643545e85b5d966b.oss-accelerate.aliyuncs.com | bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns |
| 718c257 | dh122 | 30122 | puTtoP12cKxTjrEo8m1iyHfEI92RK5Sb | music.163.com→www.sohu.com | 37cad3c6850102de.gz.bceos.com | ldp.swtacwpthqoe.cyfueitnswummxsjngda |
| 718xssp20 | dh139 | 30139 | htHtoU17cKxTjwVh1m2iyHfEI39RG1Cw | share.note.youdao.com→www.bootcdn.cn | bf6d955b81de7c44.gz.bceos.com | cii.gjjvikjqhhupaab.aaoknxedxpgnwa |
| 714cpk28 | dh146 | 30146 | erPtoD19cKxTjrCo4m1iyHfEI18RK8Bu | 未知 | a95f6c629e0324ad.gz.bceos.com | ldp.swtacwpthqoe... |
| 710cpa4 | dh164 | 30164 | gpStoF73cUxRjrTo3m5iyHfDI12RK3oL | static.zhihu.com | 未知 | uqu.ikvsdnwtnfto.cxveccaubkkjfvlknq |

---

## 九、完整函数地址表

### 9.1 libgojni.so函数

| 函数 | Ghidra地址 | 源码位置 |
|------|-----------|---------|
| FetchForwarderFixedTuple | 0x53f900 | forwarder_control.go:130-208 |
| signForwarderHelloMAC | 0x53f2a0 | forwarder_control.go |
| randomForwarderNonce | 0x43f7c0 | forwarder_control.go |
| fetchForwarderControlPlane | (kem_decomp.c中) | forwarder_control.go |
| initPskExt | 0x5ce805 | |
| setPskToUConn | 0x4be3c5 | u_session_controller.go:197 |
| obfsConn.Write | 0x544c80 | obfs.go:31-45 |
| obfsConn.writeFrame | 0x544d60 | obfs.go:48-60 |
| obfsConn.Read | (getPayload) | obfs.go |
| relayObfs.func1 | 0x549c30 | proxy.go:345-359 |
| getPayload | 0x538270 | obfs.go |
| sdkCacheFile.getPayload | 0x538270 | |

### 9.2 tgnet.so函数

| 函数 | 地址 | 大小 | 用途 |
|------|------|------|------|
| encryptKeyWithSecret | 0xdd3cd4 | | SHA256(data+auth_key[:16])→AES key |
| sendRequest | 0xdd2e08 | (到0xdd3588) | AES-CFB/CTR分段加密 |
| sendRequestData | 0xdd48f8 | | 调用sendRequest |
| beginHandshake | 0xdd47c8 | | 初始化握手 |
| 0xdd2914 | 0xdd2914 | | handshake初始化(获取session) |
| 0xdbaf70 | 0xdbaf70 | | 获取session(从ConnectionsManager) |
| 0x15cb8c8 | 0x15cb8c8 | | Go字符串复制函数 |
| AES-CFB/CTR | 0x89f320 | | AES-CFB/CTR加密 |
| AES_encrypt | 0x89f1e0 | | AES块加密 |
| AES key expansion | 0x89f158 | | AES密钥扩展 |
| SHA256_init | 0x8c413c | | SHA256初始化 |
| SHA256_update | 0x8c4178 | | SHA256更新 |
| SHA256_final | 0x8c4290 | | SHA256最终输出 |
| random(0x8ae1d8) | 0x8ae1d8 | | 真随机数(getrandom) |
| getrandom | 0x8be05c | | Linux syscall 0x116 |
| aes_ige_encrypt | 0x14da56c | 108 | AES-IGE加密(不被sendRequest调用) |
| aes_ige_decrypt | 0x14da5d8 | 108 | AES-IGE解密 |
| AES-IGE main | 0x8ddfd0 | | AES-IGE实际实现 |
| getAuthKey | 0xdbd9d4 | 312 | 获取auth_key(Datacenter+0x168) |
| getPermanentAuthKeyId | 0xdbe49c | 8 | 获取auth_key_id(Datacenter+0x170) |
| hasAuthKey | 0xdbe4a4 | 40 | 检查auth_key |
| hasPermanentAuthKey | 0xdbe48c | 16 | 检查永久auth_key |
| getDatacenter | 0xd967b0 | | 根据DC ID获取Datacenter |
| Connection构造 | 0xdd1d94 | | 初始化Connection对象 |

### 9.3 tgnet.so对象结构

#### Connection对象

| 偏移 | 类型 | 用途 |
|------|------|------|
| +0x18 | byte | handshake标志 |
| +0x20 | pointer | handshake消息对象 |
| +0x28 | pointer | 握手消息(2) |
| +0x40 | Go字符串 | 第一个key |
| +0x58 | Go字符串 | 临时密钥 |
| +0x168 | pointer | auth_key(ByteArray*, onHandshakeComplete设置) |
| +0x1e8 | float | 某个浮点值 |
| +0x1ec | int32 | 状态 |
| +0x1f8 | Go字符串 | 某个字段 |
| +0x210 | Go字符串 | 永久密钥/auth_key(从session复制) |
| +0x230 | pointer | ConnectionsManager |
| +0x238 | int32 | type |
| +0x23c | int32 | size |
| +0x240 | byte | type2 |
| +0x258 | int32 | 初始化值5 |
| +0x260 | pointer | 新分配的0x50字节对象 |
| +0x270 | int32 | 初始化值0x64(100) |
| +0x288 | int32 | 递增计数器 |

#### Datacenter对象

| 偏移 | 类型 | 用途 |
|------|------|------|
| +0x10 | int32 | DC ID (0-5) |
| +0x168 | pointer | 永久auth_key (NativeByteBuffer*) |
| +0x170 | int64 | auth_key_id (8字节直接值) |
| +0x1a0 | byte | auth_key标志 (0=没有, 非0=有) |
| +0x1a8 | pointer | 临时auth_key链表起始 |
| +0x1b0 | pointer | 临时auth_key链表结束 |

#### ConnectionsManager对象

| 偏移 | 类型 | 用途 |
|------|------|------|
| +0x10 | int32 | DataCenter ID |
| +0x168 | pointer | session链表1 (永久) |
| +0x178 | pointer | session链表2 (临时) |
| +0x1b8 | Go字符串 | 某个key |
| +0x1d0 | Go字符串 | 全局密钥 |
| +0x2eb | byte | 随机选择标志 |
| +0x2ec | byte | 另一个标志 |

#### NativeByteBuffer对象 (推测)

| 偏移 | 类型 | 用途 |
|------|------|------|
| +0x0 | pointer | bufferStart (有0x20 GC标记前缀) |
| +0x8 | pointer | bufferEnd |
| +0x10 | pointer | bufferCurrent |

---

## 十、Ghidra项目信息

| 项目 | 路径 | so文件 |
|------|------|--------|
| libgojni.so | /tmp/ghidra_proj_gojni/gojni_proj | /tmp/libgojni.so (8.5MB) |
| tgnet.so | /tmp/ghidra_proj_tgnet2/tgnet_proj (已删除) | /tmp/tgnet_full.so (23MB, libBeoWtwvbyJzC.so) |

**反编译结果文件**:
- /tmp/sdk_decomp.c (1104行, signForwarderHelloMAC + FetchForwarderFixedTuple + fetchForwarderControlPlane)
- /tmp/kem_decomp.c (126KB, initPskExt + setPskToUConn + signForwarderHelloMAC + FetchForwarderFixedTuple等)

**Ghidra基址**: libgojni.so的Ghidra地址 = 文件偏移 + 0x100000

---

## 十一、APK内存中的DEADBEEF帧

在APP内存(0x4000010b10-0x40000ac5d0)找到的DEADBEEF帧:

| 地址 | sublen | payload_len | pad | 内容 |
|------|--------|-------------|-----|------|
| 0x4000010db0 | 0 | 105 | 2 | "http/1.1" HTTP响应 |
| 0x4000010e56 | 0 | 105 | 49 | TLS数据(0x03 0x03...) |
| 0x4000010f40 | 0 | 105 | 29 | TLS数据 |
| 0x4000011000 | 0 | 105 | 20 | 嵌套DEADBEEF |
| 0x40000110b0 | 0 | 105 | 54 | "30139" 端口号 |
| 0x40000110e0 | 0 | 105 | 25 | "30139" + IP地址 |
| 0x4000011120 | 0 | 105 | 53 | IP地址(8.163.110.136等) |
| 0x4000074f71 | 0 | 5 | 4 | "test\n" 测试数据 |
| 0x400008fb00 | 0 | 988 | 62 | 高entropy加密数据 |
| 0x40000ac5d0 | 0 | 329 | 36 | "127.0.0.1:60139" 本地代理 |

---

## 十二、sdk_forwarder_fixed.json

### 当前内容 (2026-07-26 22:12)

```json
{
  "version": 0,
  "fixed": {},
  "app_line_ips": [
    "8.163.112.72",
    "114.132.247.112",
    "8.138.196.64",
    "8.148.251.123",
    "8.163.42.186",
    "8.163.110.136",
    "111.230.72.238",
    "8.163.113.64",
    "103.45.129.234",
    "139.199.159.229",
    "103.120.90.51",
    "43.136.38.151",
    "123.207.40.186",
    "8.148.195.131",
    "42.194.181.18"
  ],
  "app_line_port": 30139,
  "saved_at_unix": 1785075148
}
```

### APP文件列表

| 文件 | 大小 | 用途 |
|------|------|------|
| tgnet.dat | 1100B | DC配置(5个DC, 含256B高entropy数据) |
| dc1conf.dat | 40B | DC1配置 |
| exid.dat | 57B | exid数据 |
| stats2.dat | 612B | 统计数据 |
| sdk_forwarder_fixed.json | 432B | app_line_ips |
| cache4.db | 6.3MB | 缓存数据库 |

### tgnet.dat结构

```
偏移0x00: 48 04 00 00 → 总长度=0x448=1096
偏移0x04: 05 00 00 00 → 5个DC
偏移0x08: 37 97 79 bc → 时间戳
偏移0x0e: "zh-cn" → 语言
偏移0x70: "127.0.0.1" → 本地地址
偏移0x80: eb ea 00 00 → 0xeaeb=60139 (本地端口!)
偏移0xa0-0x1a0: 256字节高entropy数据 (SHA1不匹配auth_key_id)
偏移0x1a0+: 256字节高entropy数据 (第二个DC?)
```

---

## 十三、MITM代理测试

### 13.1 mitmmlkem (utls后端)

- 前端: 标准crypto/tls
- 后端: utls Chrome115_PQ_PSK
- 截获: 1163B+1169B+395B (固定, APP→MITM的DEADBEEF)
- auth_key_id: 8c01b731e516801b (旧会话)

### 13.2 mitmfront (标准crypto/tls前端)

- 前端: 标准crypto/tls + KeyLogWriter
- 后端: utls Chrome115_PQ_PSK
- 截获: 614B+327B (不同于mitmmlkem)
- auth_key_id: 12ad461e27b5c760 (前端会话)
- 获取: 17435个前端MasterSecret

### 13.3 重放测试

| 发送 | 结果 |
|------|------|
| 1163B only | EOF |
| 1163+1169B | 1671B响应 |
| 1163+1169+395B | 1835B响应 (12个DEADBEEF) |
| 1163+1169+395B (完整) | 2041B响应 (13个DEADBEEF, 每帧105B payload) |
| 395B only | EOF |
| DEADBEEF+JSON (无认证) | 302 (HTTP重定向) |
| 重放→raw JSON | DEADBEEF响应 (105B加密payload) |

### 13.4 响应分析

- 认证响应: 172B = 1个DEADBEEF帧(105B payload)
- JSON响应: 158B = 1个DEADBEEF帧(105B payload)
- 完整响应: 2041B = 13个DEADBEEF帧(每帧105B payload)
- 所有payload都是高entropy(MTProto加密)
- **需要auth_key解密响应!**

---

## 十四、关键错误修正记录

| 之前的结论 | 修正后的结论 | 证据 |
|-----------|-------------|------|
| auth_key=master_secret | 错误! auth_key不来自TLS | 前端17435个MS×SHA1→0匹配 |
| auth_key_id=SHA1(auth_key)[:8] | 错误! auth_key_id=Datacenter+0x170 | getPermanentAuthKeyId(0xdbe49c)反编译 |
| 加密是AES-IGE | 错误! 加密是AES-CFB/CTR | 0x89f320反编译(逐字节XOR+AES_encrypt) |
| encryptKeyWithSecret=HMAC-SHA256 | 错误! 只是普通SHA256 | 0x8c413c(SHA256_init)没有ipad/opad |
| DEADBEEF payload=akid+msgkey+encrypted | 错误! payload=原始TCP数据 | writeFrame(0x544d60)反编译 |
| 1163B是forwarder control | 错误! 1163B是MTProto握手 | payload=auth_key_id+msg_key+encrypted |
| auth_key只用32字节 | 部分错误! 只用前16字节 | 0xdd3d48: min(keylen, 16) |
| DEADBEEF在tgnet.so中生成 | 错误! 在libgojni.so中 | writeFrame=0x544d60, obfsConn |

---

## 十五、当前状态总结

### 已完成 (95%)

1. ✅ DNS TXT → AES-CBC → 控制面IP
2. ✅ .dat下载 → AES-CBC → 3个代理节点
3. ✅ control_refresh_addr = 123.207.40.186:30139
4. ✅ FetchForwarderFixedTuple发送明文JSON+\n (kem_decomp.c行644)
5. ✅ MAC 8字段确认 (v1|hello|hex|uuid|sdk_ver|ver_str|ts|nonce_ts)
6. ✅ DEADBEEF帧格式确认 (writeFrame反编译, obfs.go:48-60)
7. ✅ DEADBEEF payload = 原始TCP数据 (不加密!)
8. ✅ relayObfs中继所有TCP流量 (proxy.go:345-359)
9. ✅ 1163B是MTProto握手消息 (不是forwarder control)
10. ✅ 加密方式 = AES-CFB/CTR (不是AES-IGE!)
11. ✅ encryptKeyWithSecret = SHA256 (不是HMAC!)
12. ✅ auth_key_id = Datacenter+0x170 (不是SHA1!)
13. ✅ auth_key = Datacenter+0x168 (NativeByteBuffer*)
14. ✅ auth_key = session+0x20 (从0xdbaf70获取)
15. ✅ 重放1163+1169B认证成功
16. ✅ 发送raw JSON成功 → 收到DEADBEEF响应
17. ✅ RSA私钥(2048bit)在APP内存找到
18. ✅ SecretPayload含AppLineIPs字段
19. ✅ IP在APP内存中是明文 (0x40000c6230)
20. ✅ sdk_forwarder_fixed.json可获取15个IP

### 未完成 (5%)

1. ❌ auth_key的值
   - auth_key_id不在APP内存中 (大小端序都搜索过)
   - Datacenter对象搜索→误报
   - auth_key在每次会话中不同
   - 可能被GC回收或只存在运行时

2. ❌ 解密服务端响应
   - 响应是MTProto加密的
   - 需要auth_key解密
   - auth_key无法获取

### 可行方案

给域名 → 下载APK → 在设备运行 → 读取sdk_forwarder_fixed.json → 获取15个IP
(已成功获取! json重新生成, 包含15个app_line_ips)

---

## 十六、关键文件路径

### 分析文件
- /home/ninini/Agents/APK-Research/forensics/mlkem_final.txt — 完整分析记录
- /home/ninini/Agents/APK-Research/forensics/auth_key_final_conclusion.txt — auth_key结论
- /tmp/sdk_decomp.c — Ghidra反编译(1104行)
- /tmp/kem_decomp.c — Ghidra反编译(126KB)

### so文件
- /tmp/libgojni.so — Go JNI库(8.5MB)
- /tmp/tgnet_full.so — 完整tgnet.so(23MB, libBeoWtwvbyJzC.so)

### Go源码
- /home/ninini/Agents/APK-Research/go_src/forwarder_client/ — 测试程序
- /home/ninini/Agents/APK-Research/go_src/sdk_impl/ — SDK复现

### MITM数据
- /tmp/mitm_ekm.txt — mitmfront数据(3032行, 550个MS)
- /tmp/mitm_secret.txt — mitm2数据(1296行)
- /tmp/mlkem_final.txt — mitmmlkem数据(4700行)

### 设备文件
- /data/local/tmp/msg_1163.hex — 1163B消息(MTProto握手)
- /data/local/tmp/msg_1169.hex — 1169B消息(MTProto握手)
- /data/local/tmp/msg_395.hex — 395B消息(MTProto请求)
- /data/data/.../files/sdk_forwarder_fixed.json — app_line_ips
- /data/data/.../files/tgnet.dat — DC配置

### Go标准库修改
- /home/ninini/go/src/crypto/tls/handshake_server.go — 添加SavedPreMasterSecret
- /home/ninini/go/src/crypto/tls/handshake_client.go — 添加SavedPreMasterSecretClient
