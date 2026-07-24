package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

var caCert *x509.Certificate
var caKey *rsa.PrivateKey
var logFile *os.File

func main() {
	// 加载CA证书和私钥
	caData, err := os.ReadFile("/sdcard/mitmproxy-ca.pem")
	if err != nil {
		fmt.Println("读取CA失败:", err)
		return
	}
	
	block, _ := pem.Decode(caData)
	if block == nil {
		fmt.Println("PEM解码失败")
		return
	}
	
	caPriv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// 尝试PKCS8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			fmt.Println("解析私钥失败:", err)
			return
		}
		caKey, _ = key.(*rsa.PrivateKey)
	} else {
		caKey = caPriv
	}
	
	// 解析证书部分
	certBlock, _ := pem.Decode(append(caData, []byte("\n")...))
	_ = certBlock
	
	// 用另一种方式加载
	caTLSCert, err := tls.X509KeyPair(caData, caData)
	if err != nil {
		fmt.Println("X509KeyPair失败:", err)
		return
	}
	caCert, _ = x509.ParseCertificate(caTLSCert.Certificate[0])
	
	if caCert == nil || caKey == nil {
		fmt.Println("CA或私钥为空")
		return
	}
	
	fmt.Println("CA证书加载成功")
	
	logFile, _ = os.Create("/sdcard/mitm_log.txt")
	defer logFile.Close()
	
	// 监听30122端口
	ln, err := net.Listen("tcp", "127.0.0.1:30122")
	if err != nil {
		fmt.Println("监听失败:", err)
		return
	}
	defer ln.Close()
	
	fmt.Println("TLS MITM代理监听 127.0.0.1:30122")
	
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn)
	}
}

func signCert(sni string) (tls.Certificate, error) {
	// 生成服务器私钥
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	
	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: sni,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour * 24),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{sni},
	}
	
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	
	return tls.X509KeyPair(certPEM, keyPEM)
}

func handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	
	// 先读取ClientHello获取SNI
	// 不做TLS握手，直接用peek
	buf := make([]byte, 4096)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil || n < 5 {
		fmt.Fprintf(logFile, "读取ClientHello失败: %v\n", err)
		return
	}
	
	// 解析SNI
	sni := ""
	if buf[0] == 0x16 { // TLS Handshake
		// 简单解析SNI
		sni = "mail.163.com" // 默认SNI
		// 尝试从ClientHello解析
		data := buf[5:n] // 跳过TLS record header
		if len(data) > 34 {
			// ClientHello: version(2) + random(32) + session_id + ciphers + compression + extensions
			offset := 2 + 32
			if offset < len(data) {
				sidLen := int(data[offset])
				offset += 1 + sidLen
				if offset+2 < len(data) {
					csLen := int(data[offset])<<8 | int(data[offset+1])
					offset += 2 + csLen
					if offset < len(data) {
						compLen := int(data[offset])
						offset += 1 + compLen
						if offset+2 < len(data) {
							extLen := int(data[offset])<<8 | int(data[offset+1])
							offset += 2
							extEnd := offset + extLen
							for offset+4 < extEnd && offset+4 < len(data) {
								extType := int(data[offset])<<8 | int(data[offset+1])
								eLen := int(data[offset+2])<<8 | int(data[offset+3])
								if extType == 0 && offset+4+eLen < len(data) { // SNI
									sniData := data[offset+4:offset+4+eLen]
									if len(sniData) > 5 {
										snLen := int(sniData[3])<<8 | int(sniData[4])
										if 5+snLen <= len(sniData) {
											sni = string(sniData[5:5+snLen])
										}
									}
								}
								offset += 4 + eLen
							}
						}
					}
				}
			}
		}
	}
	
	fmt.Fprintf(logFile, "SNI=%s\n", sni)
	
	// 签发证书
	cert, err := signCert(sni)
	if err != nil {
		fmt.Fprintf(logFile, "签发证书失败: %v\n", err)
		return
	}
	
	// 用签发的证书做TLS服务端
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	
	// 回退ClientHello给TLS层
	// 需要把已读取的数据放回去
	// 用一个buffered connection
	bc := &bufferedConn{Conn: clientConn, buf: buf[:n]}
	tlsConn := tls.Server(bc, tlsConfig)
	err = tlsConn.Handshake()
	if err != nil {
		fmt.Fprintf(logFile, "TLS服务端握手失败: %v\n", err)
		return
	}
	
	fmt.Fprintf(logFile, "✅ TLS MITM握手成功 SNI=%s\n", sni)
	
	// 连接真正的服务器
	backendConn, err := tls.Dial("tcp", "8.134.93.241:30122", &tls.Config{
		InsecureSkipVerify: true,
		ServerName: sni,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			0xc00a, 0xc014, 0x0039, 0x006b, 0x0035, 0x003d,
			0xc007, 0xc009, 0xc023, 0xc011, 0xc013, 0xc027,
			0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002f,
			0x003c, 0x000a,
		},
	})
	if err != nil {
		fmt.Fprintf(logFile, "连接后端失败: %v\n", err)
		return
	}
	defer backendConn.Close()
	
	// 双向转发+记录明文
	var wg sync.WaitGroup
	wg.Add(2)
	
	go func() {
		defer wg.Done()
		buf := make([]byte, 8192)
		for {
			n, err := tlsConn.Read(buf)
			if err != nil {
				break
			}
			fmt.Fprintf(logFile, "APP明文 %d字节: %s\n", n, hex.EncodeToString(buf[:n]))
			fmt.Fprintf(logFile, "APP文本: %s\n", string(buf[:n]))
			backendConn.Write(buf[:n])
		}
	}()
	
	go func() {
		defer wg.Done()
		buf := make([]byte, 8192)
		for {
			n, err := backendConn.Read(buf)
			if err != nil {
				break
			}
			fmt.Fprintf(logFile, "SERVER明文 %d字节: %s\n", n, hex.EncodeToString(buf[:n]))
			fmt.Fprintf(logFile, "SERVER文本: %s\n", string(buf[:n]))
			tlsConn.Write(buf[:n])
		}
	}()
	
	wg.Wait()
}

type bufferedConn struct {
	net.Conn
	buf []byte
}

func (bc *bufferedConn) Read(b []byte) (int, error) {
	if len(bc.buf) > 0 {
		n := copy(b, bc.buf)
		bc.buf = bc.buf[n:]
		return n, nil
	}
	return bc.Conn.Read(b)
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
var _ = io.EOF
var _ = time.Now
