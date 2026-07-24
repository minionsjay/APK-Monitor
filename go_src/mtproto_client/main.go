package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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

var psk = []byte("pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7")

func main() {
	caPemData, _ := os.ReadFile("/sdcard/mitmproxy-ca.pem")
	caTLSCert, _ := tls.X509KeyPair(caPemData, caPemData)
	caCert, _ = x509.ParseCertificate(caTLSCert.Certificate[0])
	block, _ := pem.Decode(caPemData)
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		caKey = k
	} else if k2, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		caKey, _ = k2.(*rsa.PrivateKey)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:30139")
	if err != nil {
		fmt.Printf("监听失败: %v\n", err)
		return
	}
	fmt.Println("代理启动")
	for {
		conn, err := ln.Accept()
		if err != nil { continue }
		go handleConn(conn)
	}
}

func signCert(sni string) (tls.Certificate, error) {
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour * 24),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	buf := make([]byte, 4096)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil || n < 5 { return }

	sni := "mail.163.com"
	// 解析client_random
	var clientRandom []byte
	data := buf[5:n]
	if len(data) >= 34 {
		clientRandom = data[2:34]
	}

	cert, err := signCert(sni)
	if err != nil { return }
	bc := &bufferedConn{Conn: clientConn, buf: buf[:n]}
	tlsConn := tls.Server(bc, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tlsConn.Handshake(); err != nil { return }
	defer tlsConn.Close()

	clientState := tlsConn.ConnectionState()

	backend, err := tls.Dial("tcp", "8.138.152.138:30139", &tls.Config{
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
		fmt.Printf("后端失败: %v\n", err)
		return
	}
	defer backend.Close()

	// 用客户端EKM派生auth_key的多种方式
	labels := []string{"auth_key", "mtproto", "psk", "exporter", "EXTRA", "key", "cryption", "proxy", "master secret", "key expansion", "client write key", "server write key"}
	
	fmt.Printf("--- 新连接 ---\n")
	if clientRandom != nil {
		fmt.Printf("client_random: %s\n", hex.EncodeToString(clientRandom))
	}

	for _, label := range labels {
		// EKM 256 bytes
		ekm256, err1 := clientState.ExportKeyingMaterial(label, nil, 256)
		if err1 == nil {
			// 方法1: SHA1(EKM)[:8]
			h1 := sha1.Sum(ekm256)
			id1 := binary.LittleEndian.Uint64(h1[:8])

			// 方法2: SHA1(HMAC-SHA256(PSK, EKM))[:8]
			hm := hmac.New(sha256.New, psk)
			hm.Write(ekm256)
			ekm_hmac := hm.Sum(nil)
			h2 := sha1.Sum(ekm_hmac)
			id2 := binary.LittleEndian.Uint64(h2[:8])

			// 方法3: SHA1(SHA256(PSK + EKM))[:8]
			combined := append(append([]byte{}, psk...), ekm256...)
			h3raw := sha256.Sum256(combined)
			h3 := sha1.Sum(h3raw[:])
			id3 := binary.LittleEndian.Uint64(h3[:8])

			// 方法4: HMAC-SHA256(PSK, label) → auth_key → SHA1[:8]
			hm4 := hmac.New(sha256.New, psk)
			hm4.Write([]byte(label))
			ak4 := hm4.Sum(nil)
			h4 := sha1.Sum(ak4)
			id4 := binary.LittleEndian.Uint64(h4[:8])

			// 方法5: HMAC-SHA256(EKM, PSK) → auth_key → SHA1[:8]
			hm5 := hmac.New(sha256.New, ekm256)
			hm5.Write(psk)
			ak5 := hm5.Sum(nil)
			h5 := sha1.Sum(ak5)
			id5 := binary.LittleEndian.Uint64(h5[:8])

			fmt.Printf("label=%s id1=0x%016x id2=0x%016x id3=0x%016x id4=0x%016x id5=0x%016x\n",
				label, id1, id2, id3, id4, id5)
		}
		
		// EKM 48 bytes (master secret size)
		ekm48, err2 := clientState.ExportKeyingMaterial(label, nil, 48)
		if err2 == nil {
			h1 := sha1.Sum(ekm48)
			id1 := binary.LittleEndian.Uint64(h1[:8])
			
			hm := hmac.New(sha256.New, psk)
			hm.Write(ekm48)
			h2 := sha1.Sum(hm.Sum(nil))
			id2 := binary.LittleEndian.Uint64(h2[:8])

			fmt.Printf("label=%s(48) id1=0x%016x id2=0x%016x\n", label, id1, id2)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		b := make([]byte, 8192)
		for {
			n, err := tlsConn.Read(b)
			if err != nil { break }
			// 提取APP消息的auth_key_id
			payload := b[6:n] // skip DEADBEEF(4)+sublen(2)
			if len(payload) >= 2 {
				plen := int(binary.BigEndian.Uint16(payload[:2]))
				if plen > 0 && len(payload) > 2 {
					inner := payload[3:] // skip payload_len(2)+padding_len(1)
					if len(inner) >= 8 {
						appAuthId := binary.LittleEndian.Uint64(inner[:8])
						fmt.Printf("APP_AUTH_KEY_ID=0x%016x\n", appAuthId)
					}
				}
			}
			backend.Write(b[:n])
		}
	}()
	go func() {
		defer wg.Done()
		b := make([]byte, 8192)
		for {
			n, err := backend.Read(b)
			if err != nil { break }
			tlsConn.Write(b[:n])
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
