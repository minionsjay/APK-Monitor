#!/bin/bash
# Redroid auto-start on reboot
sleep 5
sudo insmod /home/ubuntu/binder_linux.ko 2>/dev/null
sudo mkdir -p /dev/binderfs
sudo mount -t binder binder /dev/binderfs 2>/dev/null
sudo docker start redroid 2>/dev/null
echo "Redroid started at $(date)"
