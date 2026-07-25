package main

import (
	"encoding/hex"
	"fmt"

	sdk "sdk_impl/sdk"
)

func main() {
	s := &sdk.SDK{
		AESKey:     "htHtoU17cKxTjwVh1m2iyHfEI39RG1Cw",
		AppDomain:  "sdkghug139.cwenku.com",
		AppPort:    30139,
		AppName:    "dh139",
		SDKVersion: "4.0.1",
		DeviceUUID: "740176FFFFFFEEFFFFFFF8FFFFFFB8FFFFFFF414FFFFFFA561FFFFFFA66A52FFFFFFADFFFFFF9B7E544861FFFFFFAD",
	}

	fmt.Println("=== 1. DNS TXT ===")
	ip, _ := s.ResolveControlPlane()
	fmt.Printf("IP: %s\n", ip)

	fmt.Println("\n=== 2. .dat ===")
	groups, _ := s.FetchNodeGroups("https://b2eadc6be5be0722.oss-accelerate.aliyuncs.com/5815c1738b945fed.dat")
	fmt.Printf("Nodes: %v\n", groups.NodesA)

	fmt.Println("\n=== 3. nonce/label ===")
	nonce := sdk.RandomNonce()
	label := sdk.RandomLabel()
	fmt.Printf("nonce: %s\nlabel: %s\n", nonce, label)

	fmt.Println("\n=== 4. MAC ===")
	fmt.Printf("MAC: %s\n", s.SignForwarderHelloMAC(nonce, label))

	fmt.Println("\n=== 5. DEADBEEF ===")
	frame := sdk.BuildDeadBEEFFrame([]byte(`{"test":"data"}`))
	fmt.Printf("frame: %d bytes, magic=%x\n", len(frame), frame[:4])

	fmt.Println("\n=== 6. AES-IGE ===")
	// 测试AES-IGE加密解密
	key := make([]byte, 32)
	iv := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(i + 32)
	}
	plaintext := make([]byte, 64)
	for i := range plaintext {
		plaintext[i] = byte(i * 2)
	}

	encrypted, err := sdk.AESIGEEncrypt(key, iv, plaintext)
	if err != nil {
		fmt.Printf("加密失败: %v\n", err)
	} else {
		fmt.Printf("明文: %x\n", plaintext[:16])
		fmt.Printf("密文: %x\n", encrypted[:16])
	}

	decrypted, err := sdk.AESIGEDecrypt(key, iv, encrypted)
	if err != nil {
		fmt.Printf("解密失败: %v\n", err)
	} else {
		match := "✅"
		for i := range plaintext {
			if plaintext[i] != decrypted[i] {
				match = "❌"
				break
			}
		}
		fmt.Printf("解密: %x\n", decrypted[:16])
		fmt.Printf("验证: %s (加密→解密一致性)\n", match)
	}

	fmt.Println("\n=== 7. MTProto v2 ===")
	// 模拟master_secret作为auth_key
	masterSecret := make([]byte, 48)
	for i := range masterSecret {
		masterSecret[i] = byte(i + 1)
	}

	// MTProto v2加密
	mtData := make([]byte, 32)
	for i := range mtData {
		mtData[i] = byte('A' + i)
	}
	mtEnc, err := sdk.MTProtoEncrypt(masterSecret, mtData)
	if err != nil {
		fmt.Printf("MTProto加密失败: %v\n", err)
	} else {
		fmt.Printf("auth_key_id: %x\n", mtEnc[:8])
		fmt.Printf("msg_key: %x\n", mtEnc[8:24])
		fmt.Printf("encrypted: %x\n", mtEnc[24:40])
		fmt.Printf("总长度: %d bytes\n", len(mtEnc))

		// 解密验证
		mtDec, err := sdk.MTProtoDecrypt(masterSecret, mtEnc)
		if err != nil {
			fmt.Printf("MTProto解密失败: %v\n", err)
		} else {
			match := "✅"
			for i := range mtData {
				if mtData[i] != mtDec[i] {
					match = "❌"
					break
				}
			}
			fmt.Printf("解密验证: %s\n", match)
		}
	}

	fmt.Println("\n=== 8. MTProto v1 ===")
	mtEnc1, err := sdk.MTProtoEncryptV1(masterSecret, mtData)
	if err != nil {
		fmt.Printf("MTProto v1加密失败: %v\n", err)
	} else {
		fmt.Printf("auth_key_id: %x\n", mtEnc1[:8])
		fmt.Printf("msg_key: %x\n", mtEnc1[8:24])
		fmt.Printf("总长度: %d bytes\n", len(mtEnc1))
	}

	fmt.Println("\n=== 9. auth_key_id ===")
	id := sdk.AuthKeyID(masterSecret)
	fmt.Printf("master_secret: %s...\n", hex.EncodeToString(masterSecret[:8]))
	fmt.Printf("auth_key_id: %s\n", id)

	fmt.Println("\n=== 完成 ===")
}
