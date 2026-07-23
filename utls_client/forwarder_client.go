package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
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
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	appName := "dh151"
	psk := "pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7"
	port := 30151
	sni := "bilibili.com"
	nodes := []string{"106.53.12.54", "193.112.206.154", "8.138.41.144"}

	// 尝试多种格式
	nonce := randomNonce()
	mac := signMAC(psk, nonce)

	formats := []struct {
		{"JSON+newline", append(marshal(HelloRequest{A: appName, B: hex.EncodeToString(randomNonceBytes()), C: mac}), 0x0a)},
		{"JSON+newline+psk", append(marshal(HelloRequest{A: appName, B: hex.EncodeToString(randomNonceBytes()), C: mac, D: psk}), 0x0a)},
		{"JSON+newline+psk_as_A", append(marshal(HelloRequest{A: psk, B: appName, C: hex.EncodeToString(randomNonceBytes())}), 0x0a)},
	}{
		{"JSON+A+B+C (DEADBEEF)", makeDeadbeef(marshal(HelloRequest{A: appName, B: hex.EncodeToString(randomNonceBytes()), C: mac}))},
		{"JSON+A+B+C (newline)", append(marshal(HelloRequest{A: appName, B: hex.EncodeToString(randomNonceBytes()), C: mac}), '\n')},
		{"JSON+A+B+C+D=psk (DEADBEEF)", makeDeadbeef(marshal(HelloRequest{A: appName, B: hex.EncodeToString(randomNonceBytes()), C: mac, D: psk}))},
		{"JSON+A=psk+B+C (newline)", append(marshal(HelloRequest{A: psk, B: appName, C: hex.EncodeToString(randomNonceBytes())}), '\n')},
		{"JSON+A+B=hex_nonce+C (DEADBEEF)", makeDeadbeef(marshal(HelloRequest{A: appName, B: hex.EncodeToString(randomNonceBytes()), C: mac}))},
	}

	for _, f := range formats {
		log.Printf("=== %s (%d bytes) ===", f.name, len(f.data))
		log.Printf("  hex: %s", hex.EncodeToString(f.data[:min(20, len(f.data))]))

		for _, node := range nodes {
			resp, err := tryFetch(node, port, sni, f.data)
			if err != nil {
				continue
			}
			log.Printf("  ✅ 成功! %+v", resp)
			return
		}
		log.Printf("  所有节点都失败")
	}
	log.Printf("❌ 全部失败")
}

func randomNonce() uint64 {
	buf := make([]byte, 16)
	rand.Read(buf)
	return new(big.Int).SetBytes(buf[:8]).Uint64()
}

func randomNonceBytes() []byte {
	buf := make([]byte, 16)
	rand.Read(buf)
	return buf
}

func signMAC(psk string, nonce uint64) string {
	msg := "hello" + hex.EncodeToString(randomNonceBytes())
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

func marshal(req HelloRequest) []byte {
	data, _ := json.Marshal(req)
	return data
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

	uConn := utls.UClient(conn, &utls.Config{
		InsecureSkipVerify: true,
		ServerName:          sni,
		NextProtos:          []string{"cursor-control-v1"},
	}, utls.Hello360_Auto)
	err = uConn.Handshake()
	if err != nil {
		conn.Close()
		return nil, err
	}

	uConn.SetDeadline(time.Now().Add(15 * time.Second))
	_, err = uConn.Write(data)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 读取响应
	header := make([]byte, 8)
	_, err = io.ReadFull(uConn, header)
	if err != nil {
		// 尝试读取任意数据
		buf := make([]byte, 1024)
		n, _ := uConn.Read(buf)
		if n > 0 {
			log.Printf("  %s: 收到 %d bytes: %s", node, n, string(buf[:n])[:min(80, n)])
		}
		conn.Close()
		return nil, fmt.Errorf("read header: %w", err)
	}

	magic := binary.BigEndian.Uint32(header[0:4])
	if magic == DEADBEEF {
		sublen := binary.BigEndian.Uint16(header[6:8])
		subdata := make([]byte, sublen)
		_, err = io.ReadFull(uConn, subdata)
		if err != nil {
			conn.Close()
			return nil, err
		}

		var resp ForwarderResponse
		if err := json.Unmarshal(subdata, &resp); err == nil {
			conn.Close()
			return &resp, nil
		}
		// 尝试解析多个子包
		remaining := make([]byte, 8192)
		n, _ := uConn.Read(remaining)
		if n > 0 {
			allData := append(append(header, subdata...), remaining[:n]...)
			parseMultiple(allData)
		}
		conn.Close()
		return nil, fmt.Errorf("json unmarshal failed")
	}

	// 非 DEADBEEF 响应
	rest := make([]byte, 1024)
	n, _ := uConn.Read(rest)
	if n > 0 {
		log.Printf("  %s: 非 DEADBEEF (0x%08x), %d bytes: %s", node, magic, n, string(append(header, rest[:n]...))[:min(100, 8+n)])
	}
	conn.Close()
	return nil, fmt.Errorf("not deadbeef: 0x%08x", magic)
}

func parseMultiple(data []byte) {
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
