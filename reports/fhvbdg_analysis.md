# 7.16fhvbdg.apk 分析报告

**分析日期**: 2026-07-22
**APK 路径**: `/mnt/e/Work/App-analyze/Apks/0722福建下发/7.16fhvbdg(1)/7.16fhvbdg.apk`
**MD5**: 6ddca242cccc6f049300a67594ccf8d3
**大小**: 78.5 MB

---

## 1. 基本信息

| 项目 | 值 |
|------|-----|
| 应用名 | fHVbDG |
| 包名 | `ykw.pxdxtfpmxbl.xdkjurlpwdfwgtwc`（随机混淆） |
| 版本 | 52.5.46 (versionCode=19) |
| Target SDK | 34 (Android 14) |
| Min SDK | 21 |

## 2. RSA 解密的 bootstrap 配置

从 `libgojni.so` 的 Go build info 中提取 `EmbeddedPrivateKeyB64`，从 `classes3.dex` 中提取 `NetworkConstant.k`，用 RSA-2048 PKCS#1 v1.5 解密：

```json
{
  "app_domain":      "*.hycuigda052.gnzsmn.com",
  "app_domain_port": 30052,
  "app_name":        "dh052",
  "sdk_version":     "4.0.1",
  "AES-key":         "gYCtoT08cKxQjwVh4m2iyUfEI19WG3Yz"
}
```

### RSA 私钥

从 `libgojni.so` 的 Go build info (`-ldflags` 参数) 中提取，与 exdyfb 的 RSA 私钥不同。

### NetworkConstant.k

从 `classes3.dex` 偏移 0x246f13 处提取，344 字符 base64，双 base64 解码后 256 字节 RSA-2048 密文。

## 3. 与 exdyfb 的对比

| 参数 | exdyfb | fhvbdg |
|------|--------|--------|
| 包名 | bmv.tnoopkeqceeq.vigqccxfmniyfnjucuns | ykw.pxdxtfpmxbl.xdkjurlpwdfwgtwc |
| app_name | dh151 | dh052 |
| app_domain | *.qianchixt.com | *.hycuigda052.gnzsmn.com |
| app_domain_port | 30151 | 30052 |
| AES-key | qtOtoF14cKxTjrTo0m8iyHfEI18RK7Yb | gYCtoT08cKxQjwVh4m2iyUfEI19WG3Yz |
| RSA 私钥 | 不同 | 不同 |
| Go SDK | 相同 (proxy-system/sdk, im_sdk2) | 相同 |
| Go 版本 | 1.25.0 | 1.25.0 |
| libgojni.so | 8.5MB | 8.5MB |
| uTLS | v1.8.2 | v1.8.2 |

## 4. 离线获取的 C2 基础设施

### 控制面节点（从 .dat 解密，端口 30052）

```
129.204.151.112:30052
43.138.250.177:30052
8.134.177.243:30052
```

### DNS TXT 节点

```
域名: sdkcgyuf052.hycuigda052.gnzsmn.com
TXT 记录: ayLSDC8CaeKNfh5kfyPkGg==
解密 IP: 43.248.2.74
```

### .dat URL 预测算法

```python
md5(YYYYMMDD + "dh052" + "oss" + "4.0.1")  → 桶名[:16] + 文件名[16:32]
```

今日 (20260722) 的三云 URL：
- OSS: `https://012c6bfeccf596d6.oss-accelerate.aliyuncs.com/24370b526f6d4803.dat`
- BOS: `https://369a0b2092badc6f.gz.bceos.com/c642faa913c3f2cf.dat`
- ZOS: `https://1ab3a99d06d27f8a.jiangsu-10.zos.ctyun.cn/b3a33c9dab481318.dat`

### 关于 110.41.82.109:30052

`110.41.82.109` 不在今日的 .dat 控制面节点和 DNS TXT 节点中。它可能是：
1. 代理节点（由 forwarder control 协议推送，需要连控制面获取）
2. 之前运行 APP 时缓存的代理节点
3. 不同日期的节点（代理节点每天变化）

## 5. 关键权限

- CALL_PHONE + READ_CALL_LOG — 电话控制和通话记录
- RECORD_AUDIO + MODIFY_AUDIO_SETTINGS — 录音
- FOREGROUND_SERVICE_CAMERA — 后台相机
- FOREGROUND_SERVICE_MICROPHONE — 后台麦克风
- FOREGROUND_SERVICE_MEDIA_PROJECTION — 屏幕录制
- ACCESS_FINE_LOCATION — 精确定位
- READ_CLIPBOARD — 剪贴板监控
- GET_ACCOUNTS — 账号信息

## 6. DEX 和 .so 文件

### DEX（5 个，未加密）
- classes.dex: 8.6MB
- classes2.dex: 369KB
- classes3.dex: 7.3MB (含 NetworkConstant.k)
- classes4.dex: 9.3MB
- classes5.dex: 9.0MB

### .so 文件（15 个）
- libgojni.so — Go SDK 核心 (proxy-system/sdk)
- libKQhRjfjQTKQS.so — 随机命名（teamgram/tgnet 原生代码）
- libcrashsdk.so — 崩溃上报 (UC SDK)
- libumeng-spy.so — 友盟统计
- liblanguage_id_jni.so — ML Kit 语言识别

## 7. AndroidManifest 加固

Manifest 被填充到 176MB（正常几十 KB），namespace URI 用 Arabic/combining 字符混淆，阻止 androguard 解析。但 aapt 能正常解析。

## 8. 协议链路

```
1. APP 启动 → SDKBootstrap.init(context, k, "Mcgg", 30052)
2. RSA 解密 k → 得到 app_domain, AES-key, app_name, port
3. md5(YYYYMMDD+dh052+oss+4.0.1) → 桶名/文件名 → 下载 .dat
4. AES-256-CBC(IV=key[:16]) 解密 .dat → 3 个控制面节点:30052
5. DNS TXT 查询 sdkcgyuf052.hycuigda052.gnzsmn.com → AES 解密 → 节点 IP
6. 连控制面:30052 (TLS + uTLS + SNI 伪造) → forwarder control 协议
7. 获取代理节点列表 → 本地代理转发 → Telegram 流量
```

## 9. 离线复现命令

```bash
# 获取控制面节点（不需要设备）
python3 -c "
import hashlib, json, urllib.request, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

AES_KEY = b'gYCtoT08cKxQjwVh4m2iyUfEI19WG3Yz'
date = '20260722'  # YYYYMMDD
h = hashlib.md5(f'{date}dh052oss4.0.1'.encode()).hexdigest()
url = f'https://{h[:16]}.oss-accelerate.aliyuncs.com/{h[16:32]}.dat'
raw = urllib.request.urlopen(url, timeout=15).read()
cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_KEY[:16])
pt = unpad(cipher.decrypt(raw), 16)
print(json.loads(pt))
"
```
