#!/system/bin/sh
# 秒拨型换IP:只重启 tun2socks,逼它对固定秒拨端点新建上游连接 -> 新的国内出口IP
# tun/ip rule/route 都不动,毫秒级切换。批量循环里每测完一个样本调一次。
BIN=/data/local/tmp/tun2socks
. /data/local/tmp/proxy.env 2>/dev/null

if [ -z "$PROXY" ] || [ -z "$DEV" ] || [ -z "$TUN" ]; then
  echo "!! 没找到 /data/local/tmp/proxy.env,先跑 proxy_up.sh"; exit 1
fi

pkill -f "$BIN" 2>/dev/null || true
sleep 1
nohup $BIN --device $TUN --proxy "$PROXY" --interface $DEV --loglevel warn > /data/local/tmp/tun2socks.log 2>&1 &
sleep 2
if pgrep -f "$BIN" >/dev/null; then
  echo "[OK] 已换IP(tun2socks 重启)。用 proxy_verify.sh 确认出口IP变化。"
else
  echo "!! tun2socks 未起,日志:"; cat /data/local/tmp/tun2socks.log
fi
