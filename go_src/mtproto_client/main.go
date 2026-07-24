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
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

var caCert *x509.Certificate
var caKey *rsa.PrivateKey

func main() {
	caData, _ := os.ReadFile("/sdcard/mitmproxy-ca.pem")
	caTLSCert, _ := tls.X509KeyPair(caData, caData)
	caCert, _ = x509.ParseCertificate(caTLSCert.Certificate[0])
	block, _ := pem.Decode(caData)
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		caKey = k
	} else if k2, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		caKey, _ = k2.(*rsa.PrivateKey)
	}
	
	go listenPort("127.0.0.1:30122", "8.134.93.241:30122")
	go listenPort("127.0.0.1:30164", "119.29.117.106:30164")
	go listenPort("127.0.0.1:30139", "159.75.151.31:30139")
	go listenPort("127.0.0.1:30138", "175.178.12.252:30138")
	
	select {}
}

func listenPort(listenAddr, backendAddr string) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Println("监听失败", listenAddr, err)
		return
	}
	logFile, _ := os.OpenFile("/data/local/tmp/mitm_keys.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	defer logFile.Close()
	fmt.Fprintf(logFile, "监听 %s → %s\n", listenAddr, backendAddr)
	for {
		conn, err := ln.Accept()
		if err != nil { continue }
		go handleConn(conn, backendAddr, logFile)
	}
}

func signCert(sni string) (tls.Certificate, error) {
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	if err != nil { return tls.Certificate{}, err }
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func handleConn(clientConn net.Conn, backendAddr string, logFile *os.File) {
	defer clientConn.Close()
	buf := make([]byte, 4096)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil || n < 5 { return }
	
	sni := "mail.163.com"
	data := buf[5:n]
	if len(data) > 38 {
		offset := 34
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
							et := int(data[offset])<<8 | int(data[offset+1])
							eLen := int(data[offset+2])<<8 | int(data[offset+3])
							if et == 0 && offset+4+eLen < len(data) {
								sniData := data[offset+4 : offset+4+eLen]
								if len(sniData) > 5 {
									snLen := int(sniData[3])<<8 | int(sniData[4])
									if 5+snLen <= len(sniData) {
										sni = string(sniData[5 : 5+snLen])
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
	
	// 提取client_random (32字节，在ClientHello中)
	var clientRandom []byte
	if len(data) >= 34 {
		clientRandom = data[2:34] // version(2) + random(32)
	}
	
	fmt.Fprintf(logFile, "连接 SNI=%s → %s\n", sni, backendAddr)
	if clientRandom != nil {
		fmt.Fprintf(logFile, "client_random: %s\n", hex.EncodeToString(clientRandom))
	}
	
	cert, err := signCert(sni)
	if err != nil { return }
	bc := &bufferedConn{Conn: clientConn, buf: buf[:n]}
	tlsConn := tls.Server(bc, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tlsConn.Handshake(); err != nil {
		fmt.Fprintf(logFile, "TLS失败: %v\n", err)
		return
	}
	defer tlsConn.Close()
	
	// 获取server_random
	serverState := tlsConn.ConnectionState()
	_ = serverState
	
	fmt.Fprintf(logFile, "✅ TLS握手 SNI=%s\n", sni)
	
	// 连接后端
	backend, err := tls.Dial("tcp", backendAddr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			0xc00a, 0xc014, 0x0039, 0x006b, 0x0035, 0x003d,
			0xc007, 0xc009, 0xc023, 0xc011, 0xc013, 0xc027,
			0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002f,
			0x003c, 0x000a,
		},
	})
	if err != nil {
		fmt.Fprintf(logFile, "后端失败: %v\n", err)
		return
	}
	defer backend.Close()
	
	// 后端的TLS状态
	backendState := backend.ConnectionState()
	fmt.Fprintf(logFile, "backend cipher: 0x%04x\n", backendState.CipherSuite)
	
	// 记录所有明文数据
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		b := make([]byte, 8192)
		for {
			n, err := tlsConn.Read(b)
			if err != nil { break }
			fmt.Fprintf(logFile, "APP明文 %d字节: %s\n", n, hex.EncodeToString(b[:n]))
			backend.Write(b[:n])
		}
	}()
	go func() {
		defer wg.Done()
		b := make([]byte, 8192)
		for {
			n, err := backend.Read(b)
			if err != nil { break }
			fmt.Fprintf(logFile, "SERVER明文 %d字节: %s\n", n, hex.EncodeToString(b[:n]))
			tlsConn.Write(b[:n])
		}
	}()
	wg.Wait()
	fmt.Fprintf(logFile, "连接关闭\n")
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
