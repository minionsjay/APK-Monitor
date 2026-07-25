package com.proxysystem.sdk;

import android.app.Service;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

/**
 * VPN代理服务
 * 拦截手机所有流量，转发到本地SDK代理
 */
public class VPNService extends VpnService {
    private static final String TAG = "VPNService";
    private static final int LOCAL_PORT = 60139;
    
    private Thread vpnThread;
    private ParcelFileDescriptor vpnInterface;
    private boolean running = false;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "START".equals(intent.getAction())) {
            startVPN();
        } else if (intent != null && "STOP".equals(intent.getAction())) {
            stopVPN();
        }
        return START_STICKY;
    }

    private void startVPN() {
        if (running) return;
        running = true;

        // 创建VPN接口
        Builder builder = new Builder();
        builder.setSession("ProxySDK");
        builder.addAddress("10.0.0.2", 24);
        builder.addRoute("0.0.0.0", 0); // 拦截所有流量
        builder.addDnsServer("8.8.8.8");
        vpnInterface = builder.establish();

        if (vpnInterface == null) {
            Log.e(TAG, "VPN interface creation failed");
            running = false;
            return;
        }

        // 启动SDK代理
        startSDKProxy();

        // 启动流量转发线程
        vpnThread = new Thread(this::forwardTraffic);
        vpnThread.start();

        Log.i(TAG, "VPN started, local port: " + LOCAL_PORT);
    }

    private void stopVPN() {
        running = false;
        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
        }
        if (vpnInterface != null) {
            try {
                vpnInterface.close();
            } catch (Exception e) {
                Log.e(TAG, "close error: " + e);
            }
            vpnInterface = null;
        }
        stopSDKProxy();
        Log.i(TAG, "VPN stopped");
    }

    // JNI桥接
    private native void startSDKProxy();
    private native void stopSDKProxy();
    private native void setConfig(String aesKey, String proxyAddr, String sni, 
                                  String deviceUUID, int localPort);

    /**
     * 转发VPN流量到本地SDK代理
     * VPN接口 → 本地代理(127.0.0.1:60139) → TLS+DEADBEEF+MTProto → 代理节点
     */
    private void forwardTraffic() {
        ByteBuffer packet = ByteBuffer.allocate(32767);
        try {
            // 连接到本地代理
            SocketChannel localChannel = SocketChannel.open(
                new InetSocketAddress("127.0.0.1", LOCAL_PORT));
            localChannel.configureBlocking(false);

            while (running && vpnInterface != null) {
                // 读取VPN接口的数据（IP包）
                java.io.FileInputStream fis = 
                    new java.io.FileInputStream(vpnInterface.getFileDescriptor());
                int size = fis.read(packet.array());
                
                if (size > 0) {
                    packet.limit(size);
                    // 转发到本地代理
                    localChannel.write(packet);
                    packet.clear();
                }

                // 读取代理响应
                int read = localChannel.read(packet);
                if (read > 0) {
                    // 写回VPN接口
                    java.io.FileOutputStream fos = 
                        new java.io.FileOutputStream(vpnInterface.getFileDescriptor());
                    fos.write(packet.array(), 0, read);
                    packet.clear();
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "forward error: " + e);
        }
    }

    @Override
    public void onDestroy() {
        stopVPN();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        stopVPN();
        super.onRevoke();
    }
}
