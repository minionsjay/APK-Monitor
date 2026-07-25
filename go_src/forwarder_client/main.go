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
	"strings"
	"time"
)

type FwdHelloRequest struct {
	Version      string `json:"version"`
	Type         string `json:"type"`
	Nonce        string `json:"nonce"`
	DeviceUUID   string `json:"device_uuid,omitempty"`
	TimestampUnix string `json:"timestamp_unix"`
	SDKVersion   string `json:"sdk_version,omitempty"`
	MAC          string `json:"mac"`
}

func main() {
	aesKey := "htHtoU17cKxTjwVh1m2iyHfEI39RG1Cw"
	deviceUUID := "740176FFFFFFEEFFFFFFF8FFFFFFB8FFFFFFF414FFFFFFA561FFFFFFA66A52FFFFFFADFFFFFF9B7E544861FFFFFFAD"
	nonce := randomNonce()
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	msg := strings.Join([]string{"2", "hello", nonce, deviceUUID, tsStr, "2", "", ""}, ".")
	mac := hmacHex(aesKey, msg)
	
	req := FwdHelloRequest{
		Version: "2", Type: "hello", Nonce: nonce,
		DeviceUUID: deviceUUID, TimestampUnix: tsStr,
		SDKVersion: "4.0.1", MAC: mac,
	}
	jsonData, _ := json.Marshal(req)
	fmt.Printf("JSON len=%d\n\n", len(jsonData))

	node := "8.138.152.138:30139"
	
	// 各种前缀
	prefixes := []struct{ name string; data []byte }{
		// 2字节长度(大端) + JSON
		{"2B_len", append(uint16Bytes(uint16(len(jsonData))), jsonData...)},
		// 4字节长度(小端) + JSON  
		{"4B_le_len", append(uint32LEBytes(uint32(len(jsonData))), jsonData...)},
		// 4字节0 + JSON
		{"4B_zero+json", append([]byte{0,0,0,0}, jsonData...)},
		// 1字节0 + JSON
		{"1B_zero+json", append([]byte{0}, jsonData...)},
		// 2字节0 + JSON
		{"2B_zero+json", append([]byte{0,0}, jsonData...)},
		// DEADBEEF + 2B_len + JSON
		{"deadbeef+2B_len+json", append(append([]byte{0xDE,0xAD,0xBE,0xEF}, uint16Bytes(uint16(len(jsonData)))...), jsonData...)},
		// JSON + null
		{"json+null", append(jsonData, 0)},
		// JSON + newline
		{"json+newline", append(jsonData, '\n')},
	}
	
	for _, p := range prefixes {
		fmt.Printf("=== %s (len=%d) ===\n", p.name, len(p.data))
		sendAndRead(node, p.data)
	}
}

func sendAndRead(node string, data []byte) {
	conn, err := tls.Dial("tcp", node, &tls.Config{
		InsecureSkipVerify: true, ServerName: "mail.163.com",
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{0xc013, 0xc00a, 0xc014, 0x002f, 0x0035, 0x003c, 0x003d, 0x0067, 0x006b},
	})
	if err != nil { fmt.Printf("TLS失败: %v\n\n", err); return }
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(data)
	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil { fmt.Printf("结果: %v\n\n", err); return }
	
	// 检查是否是DEADBEEF响应
	if n > 4 && buf[0] == 0xDE && buf[1] == 0xAD {
		fmt.Printf("✅ DEADBEEF响应! %d字节\n", n)
		if n > 8 {
			sublen := binary.BigEndian.Uint16(buf[4:6])
			payloadLen := binary.BigEndian.Uint16(buf[6:8])
			padLen := buf[8]
			inner := buf[9+padLen:]
			fmt.Printf("sublen=%d payload_len=%d pad=%d\n", sublen, payloadLen, padLen)
			fmt.Printf("inner: %s\n\n", string(inner))
		}
	} else {
		s := string(buf[:n])
		if len(s) > 100 { s = s[:100] }
		fmt.Printf("收到 %d: %s\n\n", n, s)
	}
}

func randomNonce() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf) + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func hmacHex(key, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func uint16Bytes(n uint16) []byte {
	return []byte{byte(n >> 8), byte(n)}
}

func uint32LEBytes(n uint32) []byte {
	return []byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
}
