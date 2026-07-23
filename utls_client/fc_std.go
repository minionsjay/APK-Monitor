package main

// Forwarder Control 客户端 v2
// 用标准 crypto/tls（不是 uTLS）
// 发送 DEADBEEF + JSON 请求

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"
)

const DEADBEEF = 0xDEADBEEF

type HelloRequest struct {
	A string `json:"A,omitempty"`
	B string `json:"B,omitempty"`
	C string `json:"C,omitempty"`
	D string `json:"D,omitempty"`
	E string `json:"E,omitempty"`
}

type ForwarderResponse struct {
	AppLineIPs  []string `json:"app_line_ips"`
	AppLinePort int      `json:"app_line_port"`
	NodesA      []string `json:"nodesA"`
	NodesB      []string `json:"nodesB"`
	NodesC      []string `json:"nodesC"`
	NodesD      []string `json:"nodesD"`
	NodesE      []string `json:"nodesE"`
	Fixed       map[string]interface{} `json:"fixed"`
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	appName := "dh151"
	psk := "pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7"
	port := 30151
	nodes := []string{"106.53.12.54", "193.112.206.154", "8.138.41.144"}

	// 尝试不同的 SNI
	snis := []string{
		"bilibili.com",
		"sdkcgyuf151.qianchixt.com",
		"cursor-control-v1",
		"sdk33.01hd1.com",
		"",
	}

	nonce := randomNonce()
	mac := signMAC(psk, nonce)
	nonceStr := strconv.FormatUint(nonce, 10)

	for _, sni := range snis {
		log.Printf("=== SNI=%s ===", sni)

		// 尝试多种请求格式
		reqs := []struct {
			name string
			req  HelloRequest
		}{
			{"A=app B=nonce C=mac", HelloRequest{A: appName, B: nonceStr, C: mac}},
			{"A=app B=nonce C=mac D=psk", HelloRequest{A: appName, B: nonceStr, C: mac, D: psk}},
		}

		for _, r := range reqs {
			reqJSON, _ := json.Marshal(r.req)
			
			// 格式1: DEADBEEF + JSON
			packet := makeDeadbeef(reqJSON)
			log.Printf("  %s (DEADBEEF %d bytes): %s", r.name, len(packet), hex.EncodeToString(packet[:min(20, len(packet))]))

			for _, node := range nodes {
				resp, err := tryFetch(node, port, sni, packet)
				if err != nil {
					continue
				}
				log.Printf("  ✅ 成功! %+v", resp)
				return
			}

			// 格式2: JSON + '\n'
			newlineData := append(reqJSON, '\n')
			log.Printf("  %s (newline %d bytes)", r.name, len(newlineData))

			for _, node := range nodes {
				resp, err := tryFetch(node, port, sni, newlineData)
				if err != nil {
					continue
				}
				log.Printf("  ✅ 成功! %+v", resp)
				return
			}
		}
	}
	log.Printf("❌ 全部失败")
	os.Exit(1)
}

func randomNonce() uint64 {
	buf := make([]byte, 16)
	rand.Read(buf)
	return new(big.Int).SetBytes(buf[:8]).Uint64()
}

func signMAC(psk string, nonce uint64) string {
	msg := "hello" + strconv.FormatUint(nonce, 10)
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func makeDeadbeef(data []byte) []byte {
	packet := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(packet[0:4], DEADBEEF)
	binary.BigEndian.PutUint16(packet[4:6], 0)
	binary.BigEndian.PutUint16(packet[6:8], uint16(len(data)))
	copy(packet[8:], data)
	return packet
}

func tryFetch(node string, port int, sni string, data []byte) (*ForwarderResponse, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", node, port), 10*time.Second)
	if err != nil {
		return nil, err
	}

	// 标准 crypto/tls（不用 uTLS）
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if sni != "" {
		tlsConfig.ServerName = sni
	}

	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		conn.Close()
		return nil, err
	}

	tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	_, err = tlsConn.Write(data)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 读取响应
	header := make([]byte, 8)
	_, err = io.ReadFull(tlsConn, header)
	if err != nil {
		// 看是否有任何数据
		buf := make([]byte, 1024)
		n, _ := tlsConn.Read(buf)
		if n > 0 {
			log.Printf("    %s: 收到 %d bytes: %s", node, n, string(buf[:n])[:min(80, n)])
		}
		conn.Close()
		return nil, fmt.Errorf("read header: %w", err)
	}

	magic := binary.BigEndian.Uint32(header[0:4])
	if magic == DEADBEEF {
		sublen := binary.BigEndian.Uint16(header[6:8])
		subdata := make([]byte, sublen)
		_, err = io.ReadFull(tlsConn, subdata)
		if err != nil {
			conn.Close()
			return nil, err
		}

		var resp ForwarderResponse
		if err := json.Unmarshal(subdata, &resp); err == nil {
			conn.Close()
			return &resp, nil
		}
		log.Printf("    %s: 子包不是 JSON (%d bytes): %s", node, sublen, string(subdata[:min(80, len(subdata))]))
		conn.Close()
		return nil, fmt.Errorf("json unmarshal failed")
	}

	rest := make([]byte, 1024)
	n, _ := tlsConn.Read(rest)
	if n > 0 {
		log.Printf("    %s: 非 DEADBEEF (0x%08x): %s", node, magic, string(append(header, rest[:n]...))[:min(100, 8+n)])
	}
	conn.Close()
	return nil, fmt.Errorf("not deadbeef: 0x%08x", magic)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
