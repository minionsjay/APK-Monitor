package main

// Forwarder Control 客户端（uTLS 版本）
// 用 Chrome 指纹绕过服务端 TLS 检测

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

	utls "github.com/refraction-networking/utls"
)

const DEADBEEF = 0xDEADBEEF

var exdyfbConfig = AppConfig{
	AppName: "dh151",
	PSK:     "pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7",
	Port:    30151,
	SNI:     "sdk33.01hd1.com",
	ControlNodes: []string{"106.53.12.54", "193.112.206.154", "8.138.41.144"},
}

var fhvbdgConfig = AppConfig{
	AppName: "dh052",
	PSK:     "",
	Port:    30052,
	SNI:     "sdk.3jw0c.com",
	ControlNodes: []string{"129.204.151.112", "43.138.250.177", "8.134.177.243"},
}

type AppConfig struct {
	AppName       string
	PSK           string
	Port          int
	SNI           string
	ControlNodes  []string
}

type HelloRequest struct {
	AppName string `json:"app_name"`
	Nonce   string `json:"nonce"`
	MAC     string `json:"mac"`
}

type ForwarderResponse struct {
	AppLineIPs  []string               `json:"app_line_ips"`
	AppLinePort int                    `json:"app_line_port"`
	Fixed       map[string]interface{} `json:"fixed"`
}

func signHelloMAC(psk string, nonce uint64) string {
	msg := "hello" + strconv.FormatUint(nonce, 10)
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func randomNonce() uint64 {
	buf := make([]byte, 16)
	rand.Read(buf)
	return new(big.Int).SetBytes(buf[:8]).Uint64()
}

func makeDeadbeefPacket(jsonData []byte) []byte {
	packet := make([]byte, 8+len(jsonData))
	binary.BigEndian.PutUint32(packet[0:4], DEADBEEF)
	binary.BigEndian.PutUint16(packet[4:6], 0)
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

		// uTLS with Chrome fingerprint
		tlsConfig := &utls.Config{
			InsecureSkipVerify: true,
			ServerName:         config.SNI,
		}
		uConn := utls.UClient(conn, tlsConfig, utls.HelloChrome_Auto)
		err = uConn.Handshake()
		if err != nil {
			log.Printf("  uTLS 握手失败: %v", err)
			conn.Close()
			continue
		}
		log.Printf("  uTLS 握手成功!")

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
		uConn.SetDeadline(time.Now().Add(15 * time.Second))
		_, err = uConn.Write(packet)
		if err != nil {
			log.Printf("  发送失败: %v", err)
			conn.Close()
			continue
		}
		log.Printf("  已发送，等待响应...")

		// 读取响应头 (8 bytes)
		header := make([]byte, 8)
		_, err = io.ReadFull(uConn, header)
		if err != nil {
			log.Printf("  读取头失败: %v", err)
			// 看看有没有任何数据返回
			conn.Close()
			continue
		}

		magic := binary.BigEndian.Uint32(header[0:4])
		if magic != DEADBEEF {
			// 可能是 HTTP 302 或其他
			rest := make([]byte, 1024)
			n, _ := uConn.Read(rest)
			log.Printf("  非 DEADBEEF: 0x%08x, 额外 %d bytes", magic, n)
			if n > 0 {
				log.Printf("  原始: %s", string(append(header, rest[:n]...)))
			}
			conn.Close()
			continue
		}

		sublen := binary.BigEndian.Uint16(header[6:8])
		log.Printf("  响应头: magic=DEADBEEF, sublen=%d", sublen)

		// 读取子包数据
		subdata := make([]byte, sublen)
		_, err = io.ReadFull(uConn, subdata)
		if err != nil {
			log.Printf("  读取子包失败: %v", err)
			conn.Close()
			continue
		}
		log.Printf("  子包数据 (%d bytes)", sublen)

		// 尝试解析为 JSON（明文！）
		var resp ForwarderResponse
		err = json.Unmarshal(subdata, &resp)
		if err != nil {
			log.Printf("  JSON 解析失败: %v", err)
			log.Printf("  子包前 100 bytes: %s", hex.EncodeToString(subdata[:min(100, len(subdata))]))
			log.Printf("  ASCII: %s", string(subdata[:min(100, len(subdata))]))

			// 可能是多个子包，读取更多数据
			remaining := make([]byte, 8192)
			n, _ := uConn.Read(remaining)
			if n > 0 {
				log.Printf("  额外数据 (%d bytes)", n)
				allData := append(append(header, subdata...), remaining[:n]...)
				parseMultiplePackets(allData)
			}
			conn.Close()
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

		// 读取可能的额外子包
		remaining := make([]byte, 8192)
		n, _ := uConn.Read(remaining)
		if n > 0 {
			log.Printf("  额外数据 (%d bytes)", n)
			parseMultiplePackets(remaining[:n])
		}

		conn.Close()
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
			log.Printf("    JSON: %+v", resp)
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

	log.Printf("=== Forwarder Control 客户端 (uTLS) ===")
	log.Printf("APP: %s, 端口: %d, SNI: %s", config.AppName, config.Port, config.SNI)
	log.Printf("控制面节点: %v", config.ControlNodes)
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
