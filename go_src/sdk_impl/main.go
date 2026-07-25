package main

import (
	"crypto/sha1"
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
	ip, err := s.ResolveControlPlane()
	if err != nil {
		fmt.Printf("err: %v\n", err)
	} else {
		fmt.Printf("IP: %s\n", ip)
	}

	fmt.Println("\n=== 2. .dat ===")
	groups, err := s.FetchNodeGroups("https://b2eadc6be5be0722.oss-accelerate.aliyuncs.com/5815c1738b945fed.dat")
	if err != nil {
		fmt.Printf("err: %v\n", err)
	} else {
		fmt.Printf("Nodes: %v\n", groups.NodesA)
	}

	fmt.Println("\n=== 3. nonce/label ===")
	nonce := sdk.RandomNonce()
	label := sdk.RandomLabel()
	fmt.Printf("nonce: %s\n", nonce)
	fmt.Printf("label: %s\n", label)

	fmt.Println("\n=== 4. MAC ===")
	mac := s.SignForwarderHelloMAC(nonce, label)
	fmt.Printf("MAC: %s\n", mac)

	fmt.Println("\n=== 5. DEADBEEF ===")
	frame := sdk.BuildDeadBEEFFrame([]byte(`{"test":"data"}`))
	fmt.Printf("frame: %d bytes, magic=%x\n", len(frame), frame[:4])

	fmt.Println("\n=== 6. auth_key_id ===")
	ms := make([]byte, 48)
	for i := range ms {
		ms[i] = byte(i)
	}
	id := sdk.AuthKeyID(ms)
	h := sha1.Sum(ms)
	fmt.Printf("master_secret: %x...\n", ms[:8])
	fmt.Printf("auth_key_id: %s\n", id)
	fmt.Printf("SHA1(ms)[:8]: %s\n", hex.EncodeToString(h[:8]))
}
