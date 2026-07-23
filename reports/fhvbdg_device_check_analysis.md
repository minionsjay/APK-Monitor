# fhvbdg APK 设备校验机制分析

## 1. EmuDetector（Java 层模拟器检测）

位置: `org.telegram.messenger.EmuDetector`（classes3.dex）

### 检测方法

APP 使用 **三层检测**，任一命中即判定为模拟器：

#### Layer 1: checkBasic() — Build 属性检测

检测 `Build.*` 属性中是否包含模拟器特征：

| 属性 | 检测值 |
|------|--------|
| Build.BOARD | 包含 "nox" |
| Build.BOOTLOADER | 包含 "nox" |
| Build.FINGERPRINT | 以 "generic" 开头 |
| Build.MODEL | 包含 "google_sdk"/"droid4x"/"emulator"/"Android SDK built for x86" |
| Build.MANUFACTURER | 包含 "genymotion" |
| Build.HARDWARE | 包含 "goldfish"/"vbox86"/"android_x86"/"nox"/"ranchu" |
| Build.PRODUCT | 等于 "sdk"/"google_sdk"/"sdk_x86"/"vbox86p" 或包含 "nox" |
| Build.SERIAL | 包含 "nox" |
| Build.BRAND | 以 "generic" 开头 且 Build.DEVICE 也以 "generic" 开头 |

#### Layer 2: checkAdvanced() — 文件/网络/电话检测

| 检测项 | 方法 |
|--------|------|
| Genymotion | 检查 `/dev/socket/genyd`, `/dev/socket/baseband_genyd` |
| Andy | 检查 `fstab.andy`, `ueventd.andy.rc` |
| Nox | 检查 `fstab.nox`, `init.nox.rc`, `/BigNoxGameHD`, `/YSLauncher` |
| BlueStacks | 检查 `/Android/data/com.bluestacks.*` |
| QEMU pipes | 检查 `/dev/socket/qemud`, `/dev/qemu_pipe` |
| QEMU drivers | 读取 `/proc/tty/drivers` 和 `/proc/cpuinfo`，搜索 "goldfish" |
| IP 地址 | 执行 `netcfg`，检测 `10.0.2.15`（模拟器默认 IP） |
| QEMU 属性 | 读取 15 个系统属性（`init.svc.qemud`, `ro.hardware` 等），≥5 个命中即为模拟器 |
| 电话号码 | 检测 `15555215554` 等模拟器默认号码 |
| 设备 ID | 检测 `000000000000000`, `e21833235b6eef10`, `012345678912345` |
| IMSI | 检测 `310260000000000` |
| 运营商 | 检测 `getNetworkOperatorName() == "android"` |

#### Layer 3: checkPackageName() + EmuInputDevicesDetector

| 检测项 | 方法 |
|--------|------|
| 包名 | 检测安装了 `com.google.android.launcher.layouts.genymotion`, `com.bluestacks`, `com.bignox.app`, `com.vphone.launcher` |
| 输入设备 | 读取 `/proc/bus/input/devices`，检测 "bluestacks"/"memuhyperv"/"virtualbox" |

### 检测结果的影响

```java
// ConnectionsManager.java:651
public static int getInitFlags() {
    if (!EmuDetector.with(context).detect()) {
        return 0;           // 真机：不设 flag
    }
    return 1024;            // 模拟器：设 RequestFlagDoNotWaitFloodWait
}
```

**关键发现：检测到模拟器后，APP 并不会退出！** 只是给 `native_init` 传了一个 `1024` flag（`RequestFlagDoNotWaitFloodWait`），让 MTProto 不等待 FloodWait。

这意味着 **APP 在模拟器上也能运行**，只是行为略有不同。

## 2. Go SDK 层检测（native 层）

### checkBaiduReachable

SDK 内部会尝试连接 `www.baidu.com:443` 来验证网络连通性。这不是设备检测，而是网络检测。

### SelfCheck（自检）

Go SDK 有完整的自检机制：
- `PrivateKeyLoaded` — RSA 私钥是否加载
- `PrivateKeyValid` — RSA 私钥是否有效
- `CanDecodeSecret` — 能否解密 bootstrap
- `LastError` — 最后错误
- `TimestampUnix` — 自检时间戳

### sdk_device_uuid.txt

SDK 会将 device UUID 持久化到 `sdk_device_uuid.txt` 文件中。

### network_unreachable

SDK 会检测网络是否可用，如果不可用会标记 `network_unreachable`。

## 3. TLS 指纹检测（服务端）

服务端（43.248.2.74:30052）会检测 TLS ClientHello 指纹：
- 标准 Python TLS → 连接被重置（RST）
- Go uTLS Chrome 指纹 → TLS 握手成功
- 但 DEADBEEF 请求超时（因为 PSK 为空，forwarder control 不启用）

**这是最可能的"只有真机能打开"的原因**：服务端检测 TLS 指纹，模拟器的 TLS 指纹和真机不同。

## 4. 绕过方案

### 4.1 绕过 EmuDetector（Java 层）

在模拟器上修改 Build 属性：
```
ro.product.device: 不等于 "generic"
ro.product.model: 不包含 "google_sdk"/"emulator"
ro.hardware: 不包含 "goldfish"/"vbox86"/"ranchu"
ro.product.name: 不等于 "sdk"/"sdk_x86"
```

删除模拟器特征文件：
```
/dev/socket/genyd → 不存在
/dev/socket/qemud → 不存在
/system/bin/netcfg → 不输出 10.0.2.15
```

### 4.2 绕过 TLS 指纹检测

APP 使用 uTLS（`github.com/refraction-networking/utls`）模拟 Chrome 的 ClientHello：
- `utls.HelloChrome_Auto` — Chrome 最新版指纹
- 服务端检测到非 Chrome 指纹时重置连接

模拟器需要在 native 层使用 uTLS 库，而不是标准 TLS。

### 4.3 绕过 MTProto 设备绑定

MTProto 会话绑定到特定的 `device_uuid`（从 `RegistrationConfigManager.getNativeDeviceId()` 获取）。模拟器的 device UUID 和真机不同，服务端可能根据 UUID 推送不同的节点列表。

### 4.4 最简单的绕过方式

1. **用真机的 build.prop**：将真机的 `build.prop` 推到模拟器上覆盖
2. **用 Magisk 的 MagiskHide/Shamiko**：隐藏 root 和模拟器特征
3. **修改 libgojni.so**：patch `checkBaiduReachable` 和 `EmuDetector.detect()` 直接返回 false
4. **用 Frida hook**：hook `EmuDetector.detect()` 返回 false，hook `Build.*` 属性返回真机值

## 5. 总结

fhvbdg 的设备校验有 **三层**：

| 层 | 检测方式 | 后果 | 绕过难度 |
|----|---------|------|---------|
| Java 层 | EmuDetector (Build 属性/文件/电话) | 设 1024 flag，不阻止运行 | 简单 |
| Native 层 | SelfCheck (RSA 私钥/网络) | SDK 不初始化 | 中等 |
| 服务端 | TLS 指纹 + device_uuid | 重置连接/不推送节点 | 困难 |

**"只有真机能打开"的真正原因是服务端的 TLS 指纹检测**，而不是 Java 层的 EmuDetector（它只是设了个 flag，不阻止运行）。模拟器的 TLS ClientHello 和真机不同，服务端直接 RST 连接。
