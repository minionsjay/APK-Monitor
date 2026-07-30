#!/system/bin/sh
# 验证当前出口公网IP+归属地。不依赖手机DNS(用 --resolve 直连国内IP回显服务)。
C=/data/local/tmp/curl
# ip.3322.net 只回IP; cip.cc 回归属地。IP若失效可在宿主机重新 getent hosts 更新。
IP3322=118.184.169.32
CIPCC=8.153.105.77
echo "== 出口公网IP =="
$C -s -m 12 --resolve ip.3322.net:80:$IP3322 http://ip.3322.net; echo
echo "== 归属地 =="
$C -s -m 12 --resolve cip.cc:80:$CIPCC http://cip.cc 2>/dev/null | grep -E "IP|地址|运营商" | head -3
