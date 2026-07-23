package main

// MITM 代理：拦截 TLS 流量 + 导出 keying material + 解密 DEADBEEF
// 使用方法：
// 1. 在真机上设置 iptables 重定向到本代理
// 2. APP 的 TLS 流量经过本代理
// 3. 本代理用自签名证书做 MITM
// 4. TLS 握手后调用 ExportKeyingMaterial 获取密钥
// 5. 解密 DEADBEEF 子包数据

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	cert     tls.Certificate
	certPool *x509.CertPool
)

const DEADBEEF = 0xDEADBEEF

// 尝试各种 label 调用 ExportKeyingMaterial
var exportLabels = []string{
	"forwarder",
	"control",
	"proxy",
	"forwarder control",
	"forwarder_control",
	"exporter",
	"",
	"key",
	"aes",
	"gcm",
}

type Session struct {
	ID         string
	ClientTLS  *tls.Conn
	ServerTLS  *tls.Conn
	ExportKeys map[string][]byte // label -> key
}

func main() {
	// 生成自签名证书
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "sdk33.01hd1.com",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	cert = tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	// 控制面节点
	controlNodes := []string{"106.53.12.54", "193.112.206.154", "8.138.41.144"}
	port := 30151
	sni := "sdk33.01hd1.com"

	// 监听
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		log.Fatalf("监听失败: %v", err)
	}
	log.Printf("MITM 代理监听 0.0.0.0:%d", port)
	log.Printf("控制面节点: %v", controlNodes)
	log.Printf("SNI: %s", sni)

	// 日志文件
	logFile, _ := os.OpenFile("/home/ninini/Agents/APK-Research/mitm_keyexport.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn, controlNodes, port, sni)
	}
}

func handleConnection(clientConn net.Conn, controlNodes []string, port int, sni string) {
	defer clientConn.Close()

	// 1. 和客户端做 TLS 握手（用自签名证书）
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	clientTLS := tls.Server(clientConn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		return
	}
	log.Printf("客户端 TLS 握手成功 (from %s)", clientConn.RemoteAddr())

	// 2. 和服务端做 TLS 握手（用 uTLS 指纹？先用标准 TLS）
	// 选择一个控制面节点
	serverConn, err := net.DialTimeout("tcp", controlNodes[0]+":"+fmt.Sprintf("%d", port), 10*time.Second)
	if err != nil {
		log.Printf("连接服务端失败: %v", err)
		return
	}
	defer serverConn.Close()

	serverTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
	}
	serverTLS := tls.Client(serverConn, serverTLSConfig)
	if err := serverTLS.Handshake(); err != nil {
		log.Printf("服务端 TLS 握手失败: %v", err)
		return
	}
	log.Printf("服务端 TLS 握手成功")

	// 3. 调用 ExportKeyingMaterial 获取密钥
	// 用 GODEBUG=tlsunsafeekm=1 来绕过限制
	exportKeys := make(map[string][]byte)
	for _, label := range exportLabels {
		for _, ctx := range [][]byte{nil, []byte("")} {
			state := serverTLS.ConnectionState()
				key, err := state.ExportKeyingMaterial(label, ctx, 32)
			if err != nil {
				continue
			}
			keyName := fmt.Sprintf("%s_ctx_%v", label, ctx)
			exportKeys[keyName] = key
			log.Printf("ExportKeyingMaterial 成功! label=%s, ctx=%v, key=%s", label, ctx, hex.EncodeToString(key))
		}
	}

	if len(exportKeys) == 0 {
		log.Printf("ExportKeyingMaterial 全部失败! 可能不是 TLS 1.3")
		// 尝试 Extended Master Secret
	}

	// 4. 双向转发 + 拦截数据
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 服务端
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := clientTLS.Read(buf)
			if err != nil {
				return
			}
			data := buf[:n]
			// 检查是否是 DEADBEEF
			if len(data) >= 8 && binary.BigEndian.Uint32(data[:4]) == DEADBEEF {
				log.Printf("客户端请求 DEADBEEF (%d bytes)", n)
				parseAndDecrypt(data, exportKeys, "请求")
			}
			serverTLS.Write(data)
		}
	}()

	// 服务端 -> 客户端
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := serverTLS.Read(buf)
			if err != nil {
				return
			}
			data := buf[:n]
			if len(data) >= 8 && binary.BigEndian.Uint32(data[:4]) == DEADBEEF {
				log.Printf("服务端响应 DEADBEEF (%d bytes)", n)
				parseAndDecrypt(data, exportKeys, "响应")
			}
			clientTLS.Write(data)
		}
	}()

	wg.Wait()
}

func parseAndDecrypt(data []byte, exportKeys map[string][]byte, direction string) {
	offset := 0
	for offset+8 <= len(data) {
		if binary.BigEndian.Uint32(data[offset:offset+4]) != DEADBEEF {
			break
		}
		reserved := binary.BigEndian.Uint16(data[offset+4 : offset+6])
		sublen := binary.BigEndian.Uint16(data[offset+6 : offset+8])
		sublenInt := int(sublen)
			subdata := data[offset+8 : offset+8+sublenInt]
		
		log.Printf("  %s 子包: %d bytes (reserved=%d)", direction, sublen, reserved)
		log.Printf("    hex: %s", hex.EncodeToString(subdata[:min(32, len(subdata))]))
		
		if int(sublen) > 28 {
			aeadNonce := subdata[:12]
			ctTag := subdata[12:]
			log.Printf("    aead_nonce: %s", hex.EncodeToString(aeadNonce))
			log.Printf("    ct+tag: %d bytes", len(ctTag))
			
			// 用每个 export key 尝试解密
			for keyName, key := range exportKeys {
				block, err := aes.NewCipher(key)
				if err != nil {
					continue
				}
				gcm, err := cipher.NewGCM(block)
				if err != nil {
					continue
				}
				pt, err := gcm.Open(nil, aeadNonce, ctTag, nil)
				if err != nil {
					// 尝试附加数据
					pt, err = gcm.Open(nil, aeadNonce, ctTag, []byte("forwarder"))
					if err != nil {
						pt, err = gcm.Open(nil, aeadNonce, ctTag, []byte("proxy"))
						if err != nil {
							continue
						}
					}
				}
				log.Printf("    ✅ 解密成功! key=%s", keyName)
				log.Printf("    明文: %s", string(pt[:min(200, len(pt))]))
				
				// 如果是响应，解析 JSON
				if direction == "响应" {
					var result map[string]interface{}
					if err := json.Unmarshal(pt, &result); err == nil {
						log.Printf("    JSON: %v", result)
						// 保存到文件
						os.WriteFile("/home/ninini/Agents/APK-Research/latest_proxy_nodes.json", pt, 0644)
					}
				}
				break
			}
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

// 也尝试直接用 PSK 作为 key
func tryDirectKeys(subdata []byte) {
	keys := [][]byte{
		[]byte("pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7"),
		[]byte("qtOtoF14cKxTjrTo0m8iyHfEI18RK7Yb"),
	}
	for _, key := range keys {
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		pt, err := gcm.Open(nil, subdata[:12], subdata[12:], nil)
		if err == nil {
			log.Printf("    ✅ 直接密钥解密成功! key=%s", string(key[:10]))
			log.Printf("    明文: %s", string(pt[:min(200, len(pt))]))
		}
	}
	_ = strings.TrimSpace
}
