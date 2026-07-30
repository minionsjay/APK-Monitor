#!/system/bin/sh
# 拆除代理:恢复手机正常联网
TUN=tun0
TABLE=138
RULE_PRIO=9000
BIN=/data/local/tmp/tun2socks

ip rule del priority $RULE_PRIO 2>/dev/null || true
ip -6 rule del priority $RULE_PRIO 2>/dev/null || true
ip route flush table $TABLE 2>/dev/null || true
pkill -f "$BIN" 2>/dev/null || true
ip link set $TUN down 2>/dev/null || true
ip tuntap del mode tun dev $TUN 2>/dev/null || true
echo "[OK] 代理已拆除,恢复直连。"
