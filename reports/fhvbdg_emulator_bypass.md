# 在模拟器上运行 fhvbdg 的绕过方案

## 问题定位

APP 代码层面**没有阻止模拟器运行**：
- EmuDetector 检测到模拟器只设 flag 1024，不退出
- libgojni.so 没有 root/frida 检测
- libKQhRjfjQTKQS.so 是 WebRTC（无检测）
- AndroidManifest 所有 feature 都是 not-required

**真正的原因是服务端 TLS 指纹检测**：
- APP 用 uTLS（`github.com/refraction-networking/utls`）模拟 Chrome ClientHello
- 模拟器的系统 TLS 栈和真机不同
- 服务端检测到非 Chrome 指纹 → RST 连接
- APP 无法连接服务器 → 无法获取数据 → "打不开"

## 绕过方案

### 方案 1: Frida hook（需要 root 模拟器）

hook EmuDetector.detect() 返回 false：

```javascript
Java.perform(function() {
    var EmuDetector = Java.use("org.telegram.messenger.EmuDetector");
    EmuDetector.detect.implementation = function() {
        console.log("EmuDetector.detect() hooked → false");
        return false;
    };
    
    // 也 hook checkBasic 和 checkAdvanced
    EmuDetector.checkBasic.implementation = function() { return false; };
    EmuDetector.checkAdvanced.implementation = function() { return false; };
    EmuDetector.checkPackageName.implementation = function() { return false; };
});
```

但这只绕过 Java 层检测，不解决 TLS 指纹问题。

### 方案 2: 修改 build.prop（推荐）

将真机的 build.prop 推到模拟器：

```bash
# 从真机拉取
adb -s 192.168.1.16:39911 pull /system/build.prop /tmp/real_build.prop

# 推到模拟器
adb -s emulator-5554 push /tmp/real_build.prop /system/build.prop

# 需要修改的关键属性：
# ro.product.device=flame          # Pixel 4
# ro.product.model=Pixel 4
# ro.product.name=flame
# ro.product.brand=google
# ro.hardware=flame
# ro.product.manufacturer=Google
# ro.bootloader=...
# ro.fingerprint=google/flame/...
# ro.serialno=...
```

### 方案 3: 修改模拟器 build.prop（无需真机）

在模拟器上修改 build.prop（需要 root）：

```bash
adb -s emulator-5554 shell "su -c 'mount -o remount,rw /system'"
adb -s emulator-5554 shell "su -c 'cat > /system/build.prop << EOF
ro.product.device=flame
ro.product.model=Pixel 4
ro.product.name=flame
ro.product.brand=google
ro.product.manufacturer=Google
ro.hardware=flame
ro.bootloader=BX1A.220919.020
ro.fingerprint=google/flame/flame:13/TQ3A.220905.001/8948663:user/release-keys
ro.product.cpu.abi=arm64-v8a
ro.boot.hardware=flame
ro.kernel.qemu=0
ro.kernel.qemu.gles=0
init.svc.qemud=
init.svc.qemu-props=
qemu.hw.mainkeys=
qemu.sf.fake_camera=
qemu.sf.lcd_density=
EOF'"
adb -s emulator-5554 shell "su -c 'mount -o remount,ro /system'"
adb -s emulator-5554 reboot
```

### 方案 4: 删除模拟器特征文件

```bash
adb -s emulator-5554 shell "su -c '
  rm -f /dev/socket/genyd /dev/socket/baseband_genyd
  rm -f /dev/socket/qemud /dev/qemu_pipe
  rm -f /system/bin/netcfg
  rm -f /system/etc/init/init.nox.rc
  rm -f /fstab.nox /fstab.andy /fstab.vbox86
  rm -f /init.nox.rc /init.vbox86.rc
  rm -f /ueventd.nox.rc /ueventd.andy.rc /ueventd.vbox86.rc
'"
```

### 方案 5: 用 Magisk + Shamiko 隐藏

在模拟器上安装 Magisk + Shamiko 模块：
1. Magisk hide 掉 APP 的包名
2. Shamiko 隐藏 Magisk 本身
3. 配合 build.prop 修改

### 方案 6: 修改 APK（去掉 EmuDetector）

用 apktool 反编译，修改 smali 代码：

```bash
# 反编译
apktool d 7.16fhvbdg.apk -o fhvbdg_decoded

# 修改 EmuDetector.smali
# 将 checkBasic/checkAdvanced/checkPackageName 的返回值改为 false
# 将 detect() 的返回值改为 false

# 重新打包
apktool b fhvbdg_decoded -o fhvbdg_patched.apk

# 签名
apksigner sign --ks debug.keystore fhvbdg_patched.apk
```

具体修改：

文件: `smali_classes3/org/telegram/messenger/EmuDetector.smali`

将 `detect()` 方法改为直接返回 false：
```smali
.method public detect()Z
    .registers 2
    const/4 v0, 0x0
    return v0
.end method
```

### 方案 7: 最简单方案 — 用 ARM 模拟器 + 真机镜像

用 Google Pixel 4 的系统镜像在 AVD 中运行：
```bash
# 创建 ARM64 AVD（非 x86）
avdmanager create avd -n pixel4 --package "system-images;android-13;google_apis;arm64-v8a"

# 启动
emulator -avd pixel4 -no-snapshot -gpu host
```

这会有和真机完全相同的 build.prop、TLS 栈和硬件特征。

## 推荐方案

**最简单有效**：方案 3（修改 build.prop）+ 方案 4（删除特征文件）

如果需要完整运行（包括 TLS 连接成功）：
**方案 7（ARM64 AVD + Pixel 镜像）** — 从根本上解决 TLS 指纹问题

## 注意

即使绕过了所有检测，APP 的 Go SDK 使用的 uTLS 库内置在 libgojni.so 中，它会模拟 Chrome 的 ClientHello。所以 TLS 指纹应该和模拟器无关——uTLS 会在任何设备上生成相同的 Chrome 指纹。

如果模拟器上 APP 仍然连不上服务器，问题可能不是 TLS 指纹，而是：
1. 模拟器没有蜂窝网络 → `checkOperatorNameAndroid()` 失败
2. 模拟器没有 SIM → 某些电话检测失败
3. SDK 的 `checkBaiduReachable` 需要能访问百度

所以**方案 3（修改 build.prop）可能就够了**，因为 uTLS 会自己处理 TLS 指纹。
