#!/bin/bash
# 持续监控代理节点脚本
# 使用方法：
# 1. 真机连上后运行此脚本
# 2. 脚本会自动设置 iptables 重定向 + 启动 MITM 代理
# 3. APP 运行后 MITM 代理会自动解密代理节点
# 4. 结果保存到 /home/ninini/Agents/APK-Research/latest_proxy_nodes.json

cd /home/ninini/Agents/APK-Research

# 1. 设置 iptables 重定向（需要 root）
echo "=== 设置 iptables 重定向 ==="
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 30151 -j REDIRECT --to-port 30151'" 2>&1
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 30052 -j REDIRECT --to-port 30052'" 2>&1

# 2. 推送自签名证书到真机
echo "=== 推送证书 ==="
adb push /tmp/sdk33_cert.pem /sdcard/ 2>&1

# 3. 启动 MITM 代理（在 WSL 上）
echo "=== 启动 MITM 代理 ==="
GODEBUG=tlsunsafeekm=1 ./mitm_keyexport &
MITM_PID=$!
echo "MITM PID: $MITM_PID"

# 4. 等待 APP 运行
echo "=== 等待 APP 运行 ==="
sleep 30

# 5. 检查结果
echo "=== 检查结果 ==="
if [ -f latest_proxy_nodes.json ]; then
    echo "代理节点:"
    cat latest_proxy_nodes.json | python3 -m json.tool 2>/dev/null || cat latest_proxy_nodes.json
else
    echo "还没有获取到代理节点，检查 MITM 日志"
    tail -20 mitm_keyexport.log
fi

# 6. 清理 iptables
echo "=== 清理 ==="
adb shell "su -c 'iptables -t nat -D OUTPUT -p tcp --dport 30151 -j REDIRECT --to-port 30151'" 2>&1
adb shell "su -c 'iptables -t nat -D OUTPUT -p tcp --dport 30052 -j REDIRECT --to-port 30052'" 2>&1
kill $MITM_PID 2>/dev/null
echo "完成"
