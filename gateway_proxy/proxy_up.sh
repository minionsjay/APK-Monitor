#!/system/bin/sh
# 在手机上以 root 执行:把全机 TCP/UDP 流量强制导入 tun -> tun2socks -> 国内SOCKS5
# 用法: sh proxy_up.sh <SOCKS_IP> <SOCKS_PORT> [user] [pass]
# native socket 也被抓:靠内核 ip rule(优先级9000,压过 Android fwmark 分流),非 App 层 VPN。

BIN=/data/local/tmp/tun2socks
TUN=tun0
TUN_ADDR=198.18.0.1
TUN_MASK=15
TABLE=138
RULE_PRIO=9000

# 两种用法:
#  ① PROXY_URL='http://ip:port' 或 'socks5://user:pass@ip:port' sh proxy_up.sh
#  ② sh proxy_up.sh <ip> <port> [user] [pass]   (默认按 socks5 拼)
if [ -n "$PROXY_URL" ]; then
  PROXY="$PROXY_URL"
  hp="${PROXY_URL#*://}"; hp="${hp##*@}"; PROXY_HOST="${hp%%:*}"
else
  SOCKS_IP="$1"; SOCKS_PORT="$2"; SOCKS_USER="$3"; SOCKS_PASS="$4"
  if [ -z "$SOCKS_IP" ] || [ -z "$SOCKS_PORT" ]; then
    echo "usage: proxy_up.sh <ip> <port> [user] [pass]   或   PROXY_URL='http://ip:port' proxy_up.sh"; exit 1
  fi
  if [ -n "$SOCKS_USER" ]; then
    PROXY="socks5://${SOCKS_USER}:${SOCKS_PASS}@${SOCKS_IP}:${SOCKS_PORT}"
  else
    PROXY="socks5://${SOCKS_IP}:${SOCKS_PORT}"
  fi
  PROXY_HOST="$SOCKS_IP"
fi
echo "[*] 代理: $PROXY (host=$PROXY_HOST)"

# 找当前IPv4默认路由(Android在按netId的表里,不在main;排除dummy0)
DEFLINE=$(ip route show table all | grep '^default via' | grep -v dummy0 | grep 'dev ' | head -1)
GW=$(echo "$DEFLINE" | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}')
DEV=$(echo "$DEFLINE" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
echo "[*] 物理默认出口: gw=$GW dev=$DEV"
if [ -z "$GW" ] || [ -z "$DEV" ]; then echo "!! 找不到默认路由,退出"; exit 1; fi

echo "[*] 清理旧状态"
ip rule del priority $RULE_PRIO 2>/dev/null
ip -6 rule del priority $RULE_PRIO 2>/dev/null
ip route flush table $TABLE 2>/dev/null
ip link set $TUN down 2>/dev/null
ip tuntap del mode tun dev $TUN 2>/dev/null
killall tun2socks 2>/dev/null   # toybox 无 pkill -f,用 killall 按名杀
sleep 1

echo "[*] 建 tun"
ip tuntap add mode tun dev $TUN
ip addr add ${TUN_ADDR}/${TUN_MASK} dev $TUN
ip link set $TUN up

echo "PROXY='$PROXY'" >  /data/local/tmp/proxy.env
echo "DEV='$DEV'"     >> /data/local/tmp/proxy.env
echo "TUN='$TUN'"     >> /data/local/tmp/proxy.env

echo "[*] 启动 tun2socks"
# 注意:不能加 --interface(Android fwmark路由下SO_BINDTODEVICE会让出站包被丢);
# 防环路已由 table 138 里的 代理IP/32 via wlan0 排除路由处理。
nohup $BIN --device $TUN --proxy "$PROXY" --loglevel warn > /data/local/tmp/tun2socks.log 2>&1 </dev/null &
sleep 2
if ! pgrep -f "$BIN" >/dev/null; then echo "!! tun2socks 未启动:"; cat /data/local/tmp/tun2socks.log; exit 1; fi

echo "[*] 配路由表 $TABLE:代理服务器+本地LAN走物理网卡(防自环/防锁死adb),其余走 tun"
ip route add ${PROXY_HOST}/32 via $GW dev $DEV table $TABLE 2>/dev/null
# 关键:排除本地LAN(含 adb-over-WiFi 控制通道 + adb reverse),否则会把 adb 自己吸进隧道锁死
for net in $(ip route show table all | grep "dev $DEV " | grep -vE "default|unreachable|via|table (local|.*_local)" | awk '{print $1}' | grep '/' | sort -u); do
  ip route add $net dev $DEV table $TABLE 2>/dev/null
done
ip route add default dev $TUN table $TABLE

echo "[*] 加高优先级 ip rule(压过 fwmark 分流)"
ip rule add priority $RULE_PRIO from all lookup $TABLE
# IPv6 全部不可达,逼 App 回落到被隧道捕获的 IPv4(防 v6 漏流量)
ip -6 rule add priority $RULE_PRIO from all unreachable

echo "[*] ip rule:"; ip rule | sed -n '1,6p'
echo "[*] tun2socks 日志:"; tail -2 /data/local/tmp/tun2socks.log

# 看门狗保险:设了 WATCHDOG=秒数 就在该时间后自动拆除(防自锁死adb后要重启手机)
# 每次 proxy_up/rotate 会刷新;想取消看门狗: touch /data/local/tmp/proxy.keep
if [ -n "$WATCHDOG" ]; then
  rm -f /data/local/tmp/proxy.keep
  echo "$(date +%s)" > /data/local/tmp/proxy.wd
  ( WD_START=$(cat /data/local/tmp/proxy.wd)
    sleep "$WATCHDOG"
    # 若期间被刷新(wd文件变新)或用户按下keep,则不拆
    NOW_WD=$(cat /data/local/tmp/proxy.wd 2>/dev/null)
    [ -f /data/local/tmp/proxy.keep ] && exit 0
    [ "$NOW_WD" != "$WD_START" ] && exit 0
    sh /data/local/tmp/proxy_down.sh
  ) </dev/null >/dev/null 2>&1 &
  echo "[*] 看门狗已启:${WATCHDOG}s 后自动拆除(touch /data/local/tmp/proxy.keep 可取消)"
fi
echo "[OK] 已挂上。用 proxy_verify.sh 验证。拆除用 proxy_down.sh。"
