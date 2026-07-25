package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

func main() {
	aesKey := "htHtoU17cKxTjwVh1m2iyHfEI39RG1Cw"
	deviceUUID := "740176FFFFFFEEFFFFFFF8FFFFFFB8FFFFFFF414FFFFFFA561FFFFFFA66A52FFFFFFADFFFFFF9B7E544861FFFFFFAD"

	nonce := randomNonce()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	msg := joinStr([]string{"2", "hello", nonce, deviceUUID, ts})
	mac := hmacHex(aesKey, msg)

	req := map[string]string{
		"version":       "2",
		"type":          "hello",
		"nonce":         nonce,
		"device_uuid":   deviceUUID,
		"timestamp_unix": ts,
		"mac":           mac,
	}
	jsonData, _ := json.Marshal(req)

	node := "8.138.152.138:30139"
	
	// 方法1: 2字节大端长度 + JSON
	data1 := make([]byte, 2+len(jsonData))
	binary.BigEndian.PutUint16(data1[:2], uint16(len(jsonData)))
	copy(data1[2:], jsonData)
	
	// 方法2: 2字节大端长度 + JSON (长度含自身)
	data2 := make([]byte, 2+len(jsonData))
	binary.BigEndian.PutUint16(data2[:2], uint16(len(jsonData)+2))
	copy(data2[2:], jsonData)
	
	// 方法3: 4字节大端长度 + JSON
	data3 := make([]byte, 4+len(jsonData))
	binary.BigEndian.PutUint32(data3[:4], uint32(len(jsonData)))
	copy(data3[4:], jsonData)
	
	// 方法4: 直接JSON（无前缀）
	data4 := jsonData
	
	formats := []struct{ name string; data []byte }{
		{"2B_BE_len+json", data1},
		{"2B_BE_len_incl+json", data2},
		{"4B_BE_len+json", data3},
		{"json_only", data4},
	}
	
	for _, f := range formats {
		fmt.Printf("\n=== %s (len=%d) ===\n", f.name, len(f.data))
		sendAndRead(node, f.data)
	}
}

func sendAndRead(node string, data []byte) {
	conn, err := tls.Dial("tcp", node, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "mail.163.com",
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{0xc013, 0xc00a, 0xc014, 0x002f, 0x0035, 0x003c, 0x003d, 0x0067, 0x006b},
	})
	if err != nil { fmt.Printf("TLS失败: %v\n", err); return }
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(data)

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("读取: %v\n", err)
		return
	}
	
	// 检查响应
	if n >= 2 {
		respLen := binary.BigEndian.Uint16(buf[:2])
		fmt.Printf("收到 %d字节, 前2字节=0x%04x(%d)\n", n, respLen, respLen)
		if n > 2 {
			fmt.Printf("数据: %s\n", string(buf[2:n]))
		}
	} else {
		fmt.Printf("收到 %d字节: %x\n", n, buf[:n])
	}
}

func randomNonce() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf) + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func joinStr(fields []string) string {
	r := ""
	for i, f := range fields {
		if i > 0 { r += "." }
		r += f
	}
	return r
}

func hmacHex(key, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
