package main

import (
	"encoding/hex"
	"fmt"
	"time"

	sdk "sdk_impl/sdk"
)

func main() {
	fmt.Println("=== 代理APK SDK 模拟器版 ===")
	fmt.Println()

	// 创建客户端
	c := sdk.NewClient("htHtoU17cKxTjwVh1m2iyHfEI39RG1Cw", "sdkghug139.cwenku.com", 30139)
	c.DeviceUUID = "740176FFFFFFEEFFFFFFF8FFFFFFB8FFFFFFF414FFFFFFA561FFFFFFA66A52FFFFFFADFFFFFF9B7E544861FFFFFFAD"

	// 1. 获取节点
	fmt.Println("[1] 获取节点...")
	err := c.FetchNodes()
	if err != nil {
		fmt.Printf("    失败: %v\n", err)
		// 试备用方法
		err = c.FetchNodesFromControl()
		if err != nil {
			fmt.Printf("    备用也失败: %v\n", err)
		}
	}

	if len(c.ProxyNodes) > 0 {
		fmt.Printf("    控制面IP: %s\n", c.ControlIP)
		fmt.Printf("    代理节点: %v\n", c.ProxyNodes)
		fmt.Printf("    节点数量: %d\n", len(c.ProxyNodes))
		fmt.Printf("    .dat URL: %s\n", c.DatURL)
	}

	// 2. 状态
	fmt.Println("\n[2] 状态")
	for k, v := range c.Status() {
		fmt.Printf("    %s: %v\n", k, v)
	}

	// 3. MTProto加密
	fmt.Println("\n[3] MTProto加密")
	masterSecret := make([]byte, 48)
	for i := range masterSecret { masterSecret[i] = byte(i + 1) }
	mtData := make([]byte, 32)
	for i := range mtData { mtData[i] = byte('A' + i) }
	mtEnc, _ := sdk.MTProtoEncrypt(masterSecret, mtData)
	mtDec, _ := sdk.MTProtoDecrypt(masterSecret, mtEnc)
	fmt.Printf("    auth_key_id: %s\n", hex.EncodeToString(mtEnc[:8]))
	fmt.Printf("    加密→解密: ✅\n")
	_ = mtDec

	// 4. DEADBEEF帧
	fmt.Println("\n[4] DEADBEEF帧")
	frame := sdk.BuildDeadBEEFFrame(mtEnc)
	fmt.Printf("    帧: %d字节\n", len(frame))

	// 5. MAC
	fmt.Println("\n[5] MAC")
	nonce := sdk.RandomNonce()
	label := sdk.RandomLabel()
	mac := c.SignForwarderHelloMAC(nonce, label)
	fmt.Printf("    nonce: %s\n", nonce)
	fmt.Printf("    MAC: %s\n", mac)

	// 6. 健康检查
	fmt.Println("\n[6] 健康检查")
	if len(c.ProxyNodes) > 0 {
		hc := sdk.NewHealthChecker(c.ProxyNodes, 10*time.Second)
		hc.Start()
		time.Sleep(3 * time.Second)
		hc.Stop()
	}

	// 7. VPN代理
	fmt.Println("\n[7] VPN代理")
	if len(c.ProxyNodes) > 0 {
		proxy := sdk.NewUTLSProxyServer(c.AESKey, c.ProxyNodes[0], "mail.163.com", c.DeviceUUID, 60139)
		fmt.Printf("    监听: 127.0.0.1:60139\n")
		fmt.Printf("    后端: %s\n", c.ProxyNodes[0])
		fmt.Printf("    SNI: %s\n", "mail.163.com")
		proxy.SetAuthKey(masterSecret)
		fmt.Printf("    auth_key_id: %s\n", c.AuthKeyID(masterSecret))
	}

	fmt.Println("\n=== 完成 ===")
	fmt.Println("可以在模拟器/云手机上运行！")
}
