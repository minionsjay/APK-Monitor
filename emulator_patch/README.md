# 让样本在模拟器上运行 — 结论与方案

## 结论（从源码定死）：改 Java 层没用

"安装了打不开"的根因**不是** EmuDetector，而是 **ABI/Go 运行时**：
- `go/Seq.java` 静态块里 `System.loadLibrary("gojni"); init();` —— 一旦有代码碰到 `go.Seq`，
  立刻加载 libgojni 并**启动 ARM 原生 Go 运行时**。
- x86 模拟器靠 ARM→x86 转译跑这段 Go runtime → **SIGILL 崩溃** → 打不开。
- EmuDetector 只用来选 EGL 渲染配置 + 给 MTProto 设个 flag，**从不 exit**。所以去 EmuDetector 无效。

→ **没有源码就无法把 Go SDK 编成 x86**；靠改 APK 消不掉 SIGILL。能做的是**提高转译存活率**或**换 ARM 执行环境**。

## 方案 A（本目录已做）：只留 armeabi-v7a + 重签名

`exdyfb_v7a-only_signed.apk` —— 删掉 arm64-v8a，强制 app 走 **32 位**。
32 位 ARM 转译（Houdini）比 64 位成熟得多，在下列模拟器上跑起来概率大：

- **雷电 LDPlayer / MuMu / 夜神 Nox**（默认 Android 7/9，自带 Houdini ARM 转译）——首选
- 装原版若走 arm64 崩，就装这个 v7a-only 版

批量处理任意样本：`./strip_arm64.sh <sample.apk>`（对 new_samples/ 508 个都适用）

**注意**：
- v1 签名 → 只能装 **Android ≤10** 的模拟器（雷电/夜神/MuMu 多是 7/9，OK）；Android 11+ 装不上。
- 仍不保证成功：Houdini 32 位也可能跑崩 Go runtime，需实测。
- 若样本自校验签名可能异常（这类多数不校验）。

## 方案 B（最稳，不改 APK）：ARM 执行环境

- **ARM 云手机**（真 ARM，不崩，装原版即可）——最省事
- **ARM64 系统镜像 AVD**（x86 host 上走 QEMU 全 ARM 仿真，慢但能跑 Go）
- redroid ARM 容器（需 ARM host，或 WSL2 重编内核加 binder）

## 拿到就能跑通的目标

app 一旦在 ARM 环境跑起来，`/sdcard/Android/data/<包名>/files/sdk_forwarder_fixed.json`
就是 app_line_ips（已在真机验证）。root 直接读该文件即可，无需 UI 打开。
