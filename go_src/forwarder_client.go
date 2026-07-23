package main

// Forwarder Control 客户端
// 直接连接控制面节点，发送 hello JSON，获取代理节点列表
// 不需要真机、不需要模拟器、不需要 APK
//
// 协议流程（从 Ghidra 逆向确认）：
// 1. TLS 握手（标准 TLS，SNI=sdk33.01hd1.com）
// 2. randomForwarderNonce() → 16 字节随机 nonce
// 3. signForwarderHelloMAC(psk, nonce) → HMAC-SHA256(psk, "hello" + strconv.FormatUint(nonce))
// 4. json.Marshal({app_name, nonce, mac}) → JSON
// 5. 写 DEADBEEF + 0x0000 + uint16(len) + json_bytes
// 6. io.ReadAtLeast(8 bytes header) → 读取子包长度
// 7. io.ReadAtLeast(sublen bytes) → 读取子包数据（明文 JSON）
// 8. json.Unmarshal(response) → 解析代理节点

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	DEADBEEF = 0xDEADBEEF
)

type AppConfig struct {
	AppName   string
	PSK       string
	AESKey    string
	Port      int
	SNI       string
	ControlNodes []string
}

// exdyfb / 0714 配置
var exdyfbConfig = AppConfig{
	AppName: "dh151",
	PSK:     "pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7",
	AESKey:  "qtOtoF14cKxTjrTo0m8iyHfEI18RK7Yb",
	Port:    30151,
	SNI:     "sdk33.01hd1.com",
	ControlNodes: []string{"106.53.12.54", "193.112.206.154", "8.138.41.144"},
}

// fhvbdg 配置
var fhvbdgConfig = AppConfig{
	AppName: "dh052",
	PSK:     "", // fhvbdg 没有调用 setForwarderControl
	AESKey:  "gYCtoT08cKxQjwVh4m2iyUfEI19WG3Yz",
	Port:    30052,
	SNI:     "sdk.3jw0c.com",
	ControlNodes: []string{"129.204.151.112", "43.138.250.177", "8.134.177.243"},
}

type HelloRequest struct {
	AppName string `json:"app_name"`
	Nonce   string `json:"nonce"`
	MAC     string `json:"mac"`
}

type ForwarderResponse struct {
	AppLineIPs   []string `json:"app_line_ips"`
	AppLinePort  int      `json:"app_line_port"`
	Fixed        map[string]interface{} `json:"fixed"`
	SavedAtUnix  int64    `json:"saved_at_unix"`
	MAC          string   `json:"mac,omitempty"`
}

func signHelloMAC(psk string, nonce uint64) string {
	msg := "hello" + strconv.FormatUint(nonce, 10)
	mac := hmac.New(newSHA256, []byte(psk))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func newSHA256() hash.Hash {
	return sha256.New()
}

func randomNonce() uint64 {
	// randomForwarderNonce: crypto/rand.Read(16 bytes) → 取前 8 字节作为 uint64
	buf := make([]byte, 16)
	rand.Read(buf)
	return new(big.Int).SetBytes(buf[:8]).Uint64()
}

func makeDeadbeefPacket(jsonData []byte) []byte {
	packet := make([]byte, 8+len(jsonData))
	binary.BigEndian.PutUint32(packet[0:4], DEADBEEF)
	binary.BigEndian.PutUint16(packet[4:6], 0) // reserved
	binary.BigEndian.PutUint16(packet[6:8], uint16(len(jsonData)))
	copy(packet[8:], jsonData)
	return packet
}

func fetchProxyNodes(config AppConfig) (*ForwarderResponse, error) {
	for _, node := range config.ControlNodes {
		log.Printf("连接 %s:%d (SNI=%s)...", node, config.Port, config.SNI)
		
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", node, config.Port), 10*time.Second)
		if err != nil {
			log.Printf("  TCP 连接失败: %v", err)
			continue
		}
		
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         config.SNI,
		}
		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.Handshake()
		if err != nil {
			log.Printf("  TLS 握手失败: %v", err)
			conn.Close()
			continue
		}
		log.Printf("  TLS 握手成功!")
		
		// 构造 hello 请求
		nonce := randomNonce()
		mac := signHelloMAC(config.PSK, nonce)
		req := HelloRequest{
			AppName: config.AppName,
			Nonce:   strconv.FormatUint(nonce, 10),
			MAC:     mac,
		}
		reqJSON, _ := json.Marshal(req)
		log.Printf("  请求 JSON (%d bytes): %s", len(reqJSON), string(reqJSON))
		
		// 包装成 DEADBEEF
		packet := makeDeadbeefPacket(reqJSON)
		log.Printf("  DEADBEEF 包 (%d bytes): %s", len(packet), hex.EncodeToString(packet[:min(20, len(packet))]))
		
		// 发送
		tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
		_, err = tlsConn.Write(packet)
		if err != nil {
			log.Printf("  发送失败: %v", err)
			tlsConn.Close()
			continue
		}
		log.Printf("  已发送，等待响应...")
		
		// 读取响应头 (8 bytes: magic + reserved + sublen)
		header := make([]byte, 8)
		_, err = io.ReadFull(tlsConn, header)
		if err != nil {
			log.Printf("  读取头失败: %v", err)
			tlsConn.Close()
			continue
		}
		
		magic := binary.BigEndian.Uint32(header[0:4])
		if magic != DEADBEEF {
			log.Printf("  不是 DEADBEEF: 0x%08x", magic)
			// 可能是 HTTP 302 响应
			rest := make([]byte, 1024)
			n, _ := tlsConn.Read(rest)
			log.Printf("  原始响应: %s", string(header)+string(rest[:n]))
			tlsConn.Close()
			continue
		}
		
		sublen := binary.BigEndian.Uint16(header[6:8])
		log.Printf("  响应头: magic=0x%08x, sublen=%d", magic, sublen)
		
		// 读取子包数据
		subdata := make([]byte, sublen)
		_, err = io.ReadFull(tlsConn, subdata)
		if err != nil {
			log.Printf("  读取子包失败: %v", err)
			tlsConn.Close()
			continue
		}
		log.Printf("  子包数据 (%d bytes)", sublen)
		
		// 尝试解析为 JSON（明文）
		var resp ForwarderResponse
		err = json.Unmarshal(subdata, &resp)
		if err != nil {
			log.Printf("  JSON 解析失败: %v", err)
			log.Printf("  子包前 100 bytes: %s", hex.EncodeToString(subdata[:min(100, len(subdata))]))
			log.Printf("  ASCII: %s", string(subdata[:min(100, len(subdata))]))
			
			// 可能响应有多个子包
			// 读取剩余数据
			remaining := make([]byte, 8192)
			n, _ := tlsConn.Read(remaining)
			if n > 0 {
				log.Printf("  额外数据 (%d bytes)", n)
				parseMultiplePackets(append(append(header, subdata...), remaining[:n]...))
			}
			tlsConn.Close()
			continue
		}
		
		log.Printf("  ✅ 解析成功!")
		log.Printf("  代理节点 (%d 个):", len(resp.AppLineIPs))
		for i, ip := range resp.AppLineIPs {
			port := resp.AppLinePort
			if port == 0 {
				port = config.Port
			}
			log.Printf("    %d. %s:%d", i+1, ip, port)
		}
		
		tlsConn.Close()
		return &resp, nil
	}
	
	return nil, fmt.Errorf("所有控制面节点都失败")
}

func parseMultiplePackets(data []byte) {
	offset := 0
	for offset+8 <= len(data) {
		magic := binary.BigEndian.Uint32(data[offset : offset+4])
		if magic != DEADBEEF {
			break
		}
		sublen := binary.BigEndian.Uint16(data[offset+6 : offset+8])
		if offset+8+int(sublen) > len(data) {
			break
		}
		subdata := data[offset+8 : offset+8+int(sublen)]
		log.Printf("  子包 @%d: %d bytes", offset, sublen)
		
		var resp ForwarderResponse
		if err := json.Unmarshal(subdata, &resp); err == nil {
			log.Printf("    JSON: %v", resp)
		} else {
			log.Printf("    ASCII: %s", string(subdata[:min(80, len(subdata))]))
		}
		offset += 8 + int(sublen)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	
	config := exdyfbConfig
	if len(os.Args) > 1 && os.Args[1] == "fhvbdg" {
		config = fhvbdgConfig
	}
	
	log.Printf("=== Forwarder Control 客户端 ===")
	log.Printf("APP: %s, 端口: %d, SNI: %s", config.AppName, config.Port, config.SNI)
	log.Printf("控制面节点: %v", config.ControlNodes)
	if config.PSK == "" {
		log.Printf("⚠️ PSK 为空（fhvbdg 不使用 forwarder control）")
	}
	log.Printf("")
	
	resp, err := fetchProxyNodes(config)
	if err != nil {
		log.Printf("❌ 失败: %v", err)
		os.Exit(1)
	}
	
	// 保存结果
	result := map[string]interface{}{
		"app_name":      config.AppName,
		"app_line_ips":  resp.AppLineIPs,
		"app_line_port": resp.AppLinePort,
		"timestamp":     time.Now().Format(time.RFC3339),
	}
	
	outFile := "/home/ninini/Agents/APK-Research/proxy_nodes_latest.json"
	jsonData, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile(outFile, jsonData, 0644)
	log.Printf("结果已保存: %s", outFile)
	log.Printf("JSON: %s", string(jsonData))
}
