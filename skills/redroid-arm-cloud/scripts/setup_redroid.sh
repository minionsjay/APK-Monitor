#!/bin/bash
# Redroid Android container one-click setup for ARM64 Ubuntu 22.04
# Usage: bash setup_redroid.sh
set -e

echo "=== Redroid Android Container Setup ==="
echo "Arch: $(uname -m)  Kernel: $(uname -r)"

if [ "$(uname -m)" != "aarch64" ]; then
    echo "ERROR: Requires ARM64 architecture"
    exit 1
fi

# 1. Install Docker
echo "[1/7] Installing Docker..."
if ! command -v docker &> /dev/null; then
    sudo apt update && sudo apt install -y docker.io
fi
sudo systemctl start docker
sudo systemctl enable docker

# 2. Configure China registry mirrors
echo "[2/7] Configuring Docker mirrors..."
sudo mkdir -p /etc/docker
python3 -c "
import json
with open('/tmp/daemon.json','w') as f:
    json.dump({'registry-mirrors':['https://docker.mirrors.ustc.edu.cn','https://hub-mirror.c.163.com','https://docker.m.daocloud.io']}, f)
"
sudo cp /tmp/daemon.json /etc/docker/daemon.json
sudo systemctl restart docker

# 3. Install build dependencies
echo "[3/7] Installing build deps..."
KERNEL_VER=$(uname -r | cut -d. -f1-2)
sudo apt install -y linux-source-$KERNEL_VER flex bison libssl-dev libelf-dev bc build-essential dkms linux-headers-$(uname -r) adb

# 4. Compile binder_linux module
echo "[4/7] Compiling binder_linux..."
cd /tmp
if [ ! -d /tmp/linux-source-$KERNEL_VER ]; then
    tar xf /usr/src/linux-source-$KERNEL_VER.tar.bz2 -C /tmp/
fi
cd /tmp/linux-source-$KERNEL_VER
cp /boot/config-$(uname -r) .config
# Temporarily disable STACKPROTECTOR_PER_TASK for modules_prepare
sed -i '/ifeq.*STACKPROTECTOR_PER_TASK/,/endif/s/^/#DISABLED# /' arch/arm64/Makefile
yes "" | make oldconfig 2>&1 | tail -1
make modules_prepare 2>&1 | tail -1
# Restore (asm-offsets.h now has TSK_STACK_CANARY)
sed -i 's/#DISABLED# //' arch/arm64/Makefile
make M=drivers/android modules 2>&1 | tail -3
cp drivers/android/binder_linux.ko ~/binder_linux.ko
echo "binder_linux.ko: $(ls -lh ~/binder_linux.ko | awk '{print $5}')"
# NOTE: Do NOT compile/load ashmem_linux.ko — it causes kernel panic!

# 5. Load binder module
echo "[5/7] Loading binder..."
sudo insmod ~/binder_linux.ko 2>/dev/null || echo "binder already loaded"
sudo mkdir -p /dev/binderfs
sudo mount -t binder binder /dev/binderfs 2>/dev/null || echo "binderfs already mounted"
ls /dev/binderfs/

# 6. Start Redroid
echo "[6/7] Starting Redroid..."
sudo docker rm -f redroid 2>/dev/null
sudo docker run -d --name redroid \
    --privileged \
    -p 5555:5555 \
    -v /dev/binderfs:/dev/binderfs \
    -v ~/redroid-data:/data \
    redroid/redroid:10.0.0-latest
sleep 30
echo "Container: $(sudo docker ps --format '{{.Status}}' --filter name=redroid)"

# 7. Configure ADB
echo "[7/7] Configuring ADB..."
adb kill-server 2>/dev/null
adb start-server
adb connect 127.0.0.1:5555

# Auto-start on reboot
cat > ~/start_redroid.sh << 'EOF'
#!/bin/bash
sleep 5
sudo insmod /home/ubuntu/binder_linux.ko 2>/dev/null
sudo mkdir -p /dev/binderfs
sudo mount -t binder binder /dev/binderfs 2>/dev/null
sudo docker start redroid 2>/dev/null
EOF
chmod +x ~/start_redroid.sh
(crontab -l 2>/dev/null | grep -v start_redroid; \
 echo "@reboot /home/ubuntu/start_redroid.sh >> /home/ubuntu/redroid.log 2>&1") | crontab -

echo ""
echo "=== Setup Complete ==="
echo "ADB: adb connect <server-ip>:5555 (via SSH tunnel)"
echo "Android: $(adb -s 127.0.0.1:5555 shell getprop ro.build.version.release 2>/dev/null)"
echo "Arch: $(adb -s 127.0.0.1:5555 shell getprop ro.product.cpu.abi 2>/dev/null)"
echo ""
echo "After reboot: auto-starts via crontab @reboot"
echo "Manual restart: sudo insmod ~/binder_linux.ko && sudo mount -t binder binder /dev/binderfs && sudo docker start redroid"
