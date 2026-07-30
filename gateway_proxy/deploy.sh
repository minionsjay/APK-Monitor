#!/usr/bin/env bash
# 宿主机侧一键部署:把 tun2socks + 脚本推到手机,挂上国内SOCKS5代理,并验证出口IP
# 用法: ./deploy.sh <SOCKS_IP> <SOCKS_PORT> [user] [pass]
set -e
GP="$(cd "$(dirname "$0")" && pwd)"
ADB="${ADB:-adb}"

SOCKS_IP="$1"; SOCKS_PORT="$2"; SOCKS_USER="$3"; SOCKS_PASS="$4"
if [ -z "$SOCKS_IP" ] || [ -z "$SOCKS_PORT" ]; then
  echo "usage: ./deploy.sh <SOCKS_IP> <SOCKS_PORT> [user] [pass]"; exit 1
fi

DEV=$($ADB devices | awk 'NR==2{print $1}')
[ -z "$DEV" ] && { echo "!! 没有 adb 设备,先连手机"; exit 1; }
echo "[*] 设备: $DEV"

echo "[*] 推送文件到 /data/local/tmp"
$ADB -s "$DEV" push "$GP/tun2socks-linux-arm64" /data/local/tmp/tun2socks >/dev/null
$ADB -s "$DEV" push "$GP/proxy_up.sh"     /data/local/tmp/proxy_up.sh   >/dev/null
$ADB -s "$DEV" push "$GP/proxy_down.sh"   /data/local/tmp/proxy_down.sh >/dev/null
$ADB -s "$DEV" push "$GP/proxy_verify.sh" /data/local/tmp/proxy_verify.sh >/dev/null
$ADB -s "$DEV" shell 'chmod 755 /data/local/tmp/tun2socks /data/local/tmp/proxy_*.sh'

echo "[*] 直连出口 IP(挂代理前,作对照):"
$ADB -s "$DEV" shell 'su -c "sh /data/local/tmp/proxy_verify.sh"' || true

echo "[*] 挂代理"
$ADB -s "$DEV" shell "su -c 'sh /data/local/tmp/proxy_up.sh $SOCKS_IP $SOCKS_PORT $SOCKS_USER $SOCKS_PASS'"

echo "[*] 挂代理后出口 IP(应变为国内代理出口,且与上面不同):"
$ADB -s "$DEV" shell 'su -c "sh /data/local/tmp/proxy_verify.sh"' || true
echo "[提示] 每测一个样本后,可只重连代理(秒拨类换IP)或重跑 proxy_up 指向新出口。"
echo "[提示] 拆除: adb shell su -c 'sh /data/local/tmp/proxy_down.sh'"
