#!/bin/bash
# 把任意样本 APK 改成"只留 armeabi-v7a + 重签名",强制走 32 位 ARM 转译路径,
# 提高在 雷电/MuMu/夜神 (自带 Houdini ARM 转译, Android 7-9) 上跑起来的概率。
#
# 原理: 这类样本核心是 ARM 原生 Go 运行时(libgojni)。x86 模拟器 64 位 ARM 转译常把
#       Go runtime 跑崩(SIGILL) → "打不开"。删掉 arm64-v8a 只留 armeabi-v7a,app 走 32 位,
#       Houdini 的 32 位 ARM 转译更成熟,存活概率更高。改 EmuDetector 无效(它不拦,瓶颈是ABI)。
#
# 用法: ./strip_arm64.sh <输入.apk> [输出.apk]
# 依赖: zip, unzip, jarsigner(JDK), 一个 debug.keystore(本目录已生成)
set -e
JDK=/home/ninini/ghidra_setup/jdk-21.0.11+10/bin
KS="$(dirname "$0")/debug.keystore"
IN="$1"; OUT="${2:-${1%.apk}_v7a-only_signed.apk}"
[ -f "$IN" ] || { echo "找不到 $IN"; exit 1; }
[ -f "$KS" ] || "$JDK/keytool" -genkeypair -keystore "$KS" -alias dbg -keyalg RSA -keysize 2048 \
    -validity 10000 -storepass android -keypass android -dname "CN=Debug" >/dev/null 2>&1
cp "$IN" "$OUT"
zip -q -d "$OUT" "lib/arm64-v8a/*" 2>/dev/null || true
# 删可能存在的旧 v1 签名(v2/v3 签名块会被 zip 编辑自动破坏)
zip -q -d "$OUT" "META-INF/*.RSA" "META-INF/*.SF" "META-INF/MANIFEST.MF" 2>/dev/null || true
"$JDK/jarsigner" -keystore "$KS" -storepass android -keypass android \
    -sigalg SHA256withRSA -digestalg SHA-256 "$OUT" dbg >/dev/null 2>&1
echo "OK -> $OUT"
unzip -l "$OUT" 2>/dev/null | grep -oE "lib/[^/]+/" | sort -u
