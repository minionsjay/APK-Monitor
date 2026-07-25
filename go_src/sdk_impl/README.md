# 代理APK SDK 完整复现

## 已实现功能

### Go SDK (sdk/包)
1. DNS TXT解密 → 控制面IP ✅
2. .dat文件下载+AES-CBC解密 → 代理节点 ✅
3. AES-IGE加密/解密 ✅
4. MTProto v2加密/解密 ✅
5. DEADBEEF帧封装/解析 ✅
6. HMAC-SHA256 MAC ✅
7. RSA私钥解密SecretPayload ✅
8. auth_key_id = SHA1(master_secret)[:8] ✅
9. nonce/label生成 ✅
10. TLS配置(标准crypto/tls) ✅
11. utls代理(自定义扩展0x3374/0x754f) ✅
12. master_secret获取(KeyLogWriter) ✅
13. VPN代理服务器(双向转发) ✅
14. 状态机管理 ✅
15. 健康检查 ✅
16. 故障转移 ✅
17. gomobile JNI桥接 ✅

### Android (android/)
1. VPN Service (流量拦截) ✅
2. VPN接口创建 (0.0.0.0/0路由) ✅
3. 流量转发到本地代理 ✅
4. JNI桥接调用Go SDK ✅

## 构建步骤

### 1. 编译Go SDK为Android AAR
```bash
# 安装gomobile
go install golang.org/x/mobile/cmd/gomobile@latest

# 编译AAR
cd go_src/sdk_impl
gomobile bind -target=android/arm64 -o proxy.aar ./sdk
```

### 2. 创建Android项目
```bash
# AndroidManifest.xml需要VPN权限
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.VPN_SERVICE" />

# 启动VPN
Intent intent = new Intent(this, VPNService.class);
intent.setAction("START");
startService(intent);
```

### 3. 配置参数
```java
// 在MainActivity中配置
ProxyManager pm = ProxyManager.GetProxyManager();
pm.SetConfig(
    "htHtoU17cKxTjwVh1m2iyHfEI39RG1Cw",  // AES key
    "8.134.180.186:30139",                  // 代理节点
    "mail.163.com",                          // SNI
    "your_device_uuid",                     // 设备UUID
    60139                                    // 本地端口
);
pm.Start();
```

## 完整通信链路

```
用户APP流量
    ↓ Android VPN API拦截
127.0.0.1:60139 (本地代理监听)
    ↓ Go SDK
MTProto AES-IGE加密 (auth_key=master_secret)
    ↓
DEADBEEF封装 (magic+sublen+payload_len+padding+payload)
    ↓
TLS 1.2 (cipher=0xc013, SNI伪装, 扩展0x3374/0x754f)
    ↓
代理节点:30139 (如 8.134.180.186:30139)
    ↓
代理节点解密+转发到目标服务器
```

## 密钥体系

```
RSA私钥 (编译时嵌入)
    ↓ 解密
SecretPayload {AES-key, SNI, app_domain, ...}
    ↓
DNS TXT查询 → AES-CBC解密 → 控制面IP
    ↓
.dat文件下载 → AES-CBC解密 → 代理节点列表
    ↓
TLS握手 → master_secret (48字节)
    ↓
auth_key = master_secret (补零到256字节)
auth_key_id = SHA1(auth_key)[:8]
    ↓
MTProto AES-IGE加密: msg_key + auth_key → encrypted_data
HMAC-SHA256(AES_key, strings.Join(8字段, ".")) → MAC
```

## 还缺的部分

1. forwarder control客户端 (JSON返回EOF, 可能需要配置PSK)
2. 实际的master_secret验证 (需要在MITM代理中对比)
3. .dat URL构建算法 (shortMD5+日期+域名)
4. Android UI界面 (启动/停止/状态显示)
5. 加固壳 (XXTEA+AES-256-CBC, InMemoryDexClassLoader)
