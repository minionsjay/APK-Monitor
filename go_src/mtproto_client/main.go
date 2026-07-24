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
	"strings"
	"sync"
	"time"
)

var caCert *x509.Certificate
var caKey *rsa.PrivateKey

func main() {
	caPemData, _ := os.ReadFile("/data/local/tmp/mitmproxy-ca.pem")
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
	fmt.Println("代理启动 127.0.0.1:30139")
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

	cert, err := signCert(sni)
	if err != nil { return }
	bc := &bufferedConn{Conn: clientConn, buf: buf[:n]}
	keyLogServer := &strings.Builder{}
	tlsConn := tls.Server(bc, &tls.Config{Certificates: []tls.Certificate{cert}, KeyLogWriter: keyLogServer})
	if err := tlsConn.Handshake(); err != nil { return }

	fmt.Printf("SERVER_KEYLOG: %s\n", keyLogServer.String())

	// 用标准crypto/tls做后端，设置KeyLogWriter
	keyLogBuf := &strings.Builder{}
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
		KeyLogWriter: keyLogBuf,
	})
	if err != nil {
		fmt.Printf("后端失败: %v\n", err)
		return
	}
	defer backend.Close()

	// 输出keylog
	keyLogStr := keyLogBuf.String()
	fmt.Printf("KEYLOG: %s\n", keyLogStr)

	// 解析CLIENT_RANDOM
	for _, line := range strings.Split(keyLogStr, "\n") {
		if strings.HasPrefix(line, "CLIENT_RANDOM") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				cr := parts[1]
				ms := parts[2]
				fmt.Printf("client_random=%s master_secret=%s\n", cr, ms)

				// 用master_secret尝试各种auth_key派生
				msBytes, _ := hex.DecodeString(ms)
				psk := []byte("pPVWQxaZLPSkVrQ0uGE3ycJYgBugl6H8WY3pEfbRD0tVNEYqi4Y7")

				// 方法1: HMAC-SHA256(PSK, MS)
				hm := hmac.New(sha256.New, psk)
				hm.Write(msBytes)
				ak1 := hm.Sum(nil)
				h1 := sha1.Sum(ak1)
				fmt.Printf("HMAC(PSK,MS)_id=0x%016x\n", binary.LittleEndian.Uint64(h1[:8]))

				// 方法2: HMAC-SHA256(MS, PSK)
				hm2 := hmac.New(sha256.New, msBytes)
				hm2.Write(psk)
				ak2 := hm2.Sum(nil)
				h2 := sha1.Sum(ak2)
				fmt.Printf("HMAC(MS,PSK)_id=0x%016x\n", binary.LittleEndian.Uint64(h2[:8]))

				// 方法3: SHA256(PSK + MS)
				combined := append(append([]byte{}, psk...), msBytes...)
				ak3 := sha256.Sum256(combined)
				h3 := sha1.Sum(ak3[:])
				fmt.Printf("SHA256(PSK+MS)_id=0x%016x\n", binary.LittleEndian.Uint64(h3[:8]))

				// 方法4: 直接用MS作为auth_key
				h4 := sha1.Sum(msBytes)
				fmt.Printf("MS_direct_id=0x%016x\n", binary.LittleEndian.Uint64(h4[:8]))

				// 方法5: HMAC-SHA256(SHA256(PSK), MS)
				pskHash := sha256.Sum256(psk)
				hm5 := hmac.New(sha256.New, pskHash[:])
				hm5.Write(msBytes)
				ak5 := hm5.Sum(nil)
				h5 := sha1.Sum(ak5)
				fmt.Printf("HMAC(SHA256(PSK),MS)_id=0x%016x\n", binary.LittleEndian.Uint64(h5[:8]))

				// 方法6: PRF(MS, "auth_key", PSK)
				cs := backend.ConnectionState()
				ekm, err := cs.ExportKeyingMaterial("auth_key", psk, 256)
				if err == nil {
					h6 := sha1.Sum(ekm)
					fmt.Printf("EKM(auth_key,PSK)_id=0x%016x\n", binary.LittleEndian.Uint64(h6[:8]))
				}

				// 方法7: EKM with no context
				cs2 := backend.ConnectionState()
				ekm2, _ := cs2.ExportKeyingMaterial("auth_key", nil, 256)
				if ekm2 != nil {
					h7 := sha1.Sum(ekm2)
					fmt.Printf("EKM(auth_key,nil)_id=0x%016x\n", binary.LittleEndian.Uint64(h7[:8]))
				}
			}
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
			payload := b[6:n]
			if len(payload) >= 2 {
				plen := int(binary.BigEndian.Uint16(payload[:2]))
				if plen > 0 && len(payload) > 2 {
					inner := payload[3:]
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
