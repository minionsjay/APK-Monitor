package main

// uTLS MITM 代理 - 用 Chrome 指纹做 TLS 握手
// 记录二进制请求数据

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	utls "github.com/refraction-networking/utls"
)

const DEADBEEF = 0xDEADBEEF
const LOG_FILE = "/home/ninini/Agents/APK-Research/mitm_utls_binary.log"

var cert tls.Certificate

type HelloRequest struct {
	A string `json:"A,omitempty"`
	B string `json:"B,omitempty"`
	C string `json:"C,omitempty"`
	D string `json:"D,omitempty"`
	E string `json:"E,omitempty"`
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	
	// 生成自签名证书
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sdk33.01hd1.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	cert = tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: priv}

	// 清空日志
	os.Truncate(LOG_FILE, 0)

	listener, err := net.Listen("tcp", "0.0.0.0:30151")
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	log.Printf("uTLS MITM 代理监听 0.0.0.0:30151")
	log.Printf("日志: %s", LOG_FILE)

	// 控制面节点
	controlNodes := []string{"106.53.12.54", "193.112.206.154", "8.138.41.144"}

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handle(conn, controlNodes)
	}
}

func handle(clientConn net.Conn, controlNodes []string) {
	defer clientConn.Close()

	// 1. 和客户端做 TLS 握手（用自签名证书）
	clientTLS := tls.Server(clientConn, &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	})
	if err := clientTLS.Handshake(); err != nil {
		return
	}
	log.Printf("客户端 TLS 握手成功 (from %s)", clientConn.RemoteAddr())

	// 2. 连接服务端（用 uTLS Chrome 指纹）
	serverConn, err := net.DialTimeout("tcp", controlNodes[0]+":30151", 10*time.Second)
	if err != nil {
		log.Printf("连接服务端失败: %v", err)
		return
	}
	defer serverConn.Close()

	serverTLS := utls.UClient(serverConn, &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         "sdk33.01hd1.com",
	}, utls.HelloChrome_Auto)
	if err := serverTLS.Handshake(); err != nil {
		log.Printf("服务端 uTLS 握手失败: %v", err)
		return
	}
	log.Printf("服务端 uTLS 握手成功")

	// 3. 双向转发 + 拦截
	go forward(serverTLS, clientTLS, "请求")
	forward(clientTLS, serverTLS, "响应")
}

func forward(dst io.Writer, src io.Reader, name string) {
	buf := make([]byte, 65536)
	var pending []byte

	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		data := buf[:n]
		pending = append(pending, data...)

		// 解析 DEADBEEF 包
		for len(pending) >= 8 {
			magic := binary.BigEndian.Uint32(pending[:4])
			if magic != DEADBEEF {
				// 非 DEADBEEF，直接转发
				writeLog(name, "raw", pending)
				dst.Write(pending)
				pending = nil
				break
			}
			sublen := binary.BigEndian.Uint16(pending[6:8])
			total := 8 + int(sublen)
			if len(pending) < total {
				break // 等更多数据
			}
			packet := pending[:total]
			pending = pending[total:]

			// 记录到二进制日志
			subdata := packet[8:total]
			writeLog(name, fmt.Sprintf("DEADBEEF sublen=%d", sublen), subdata)

			// 尝试解析为 JSON
			var resp map[string]interface{}
			if json.Unmarshal(subdata, &resp) == nil {
				log.Printf("[%s] JSON: %v", name, resp)
			} else {
				log.Printf("[%s] 二进制 (%d bytes): %s", name, sublen, hex.EncodeToString(subdata[:min(40, len(subdata))]))
			}

			dst.Write(packet)
		}
	}
}

func writeLog(name, tag string, data []byte) {
	f, _ := os.OpenFile(LOG_FILE, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if f != nil {
		fmt.Fprintf(f, "=== %s %s ===\nlen=%d\nhex=%s\nascii=%s\n\n",
			name, tag, len(data),
			hex.EncodeToString(data),
			asciiString(data))
		f.Close()
	}
}

func asciiString(data []byte) string {
	s := ""
	for _, b := range data {
		if b >= 0x20 && b < 0x7F {
			s += string(b)
		} else {
			s += "."
		}
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 防止 unused
var _ = strconv.Itoa
