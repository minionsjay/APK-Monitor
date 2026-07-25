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

	utls "github.com/refraction-networking/utls"
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

	klFile, _ := os.Create("/sdcard/dual_keylog.txt")
	defer klFile.Close()
	dataFile, _ := os.Create("/sdcard/dual_data.txt")
	defer dataFile.Close()

	// 监听30138和30139
	ln38, err := net.Listen("tcp", "127.0.0.1:30138")
	if err != nil {
		fmt.Printf("listen 30138: %v\n", err)
		return
	}
	ln39, err := net.Listen("tcp", "127.0.0.1:30139")
	if err != nil {
		fmt.Printf("listen 30139: %v\n", err)
		return
	}
	fmt.Println("Dual MITM proxy started (30138+30139)")

	go acceptLoop(ln38, "30138", klFile, dataFile)
	acceptLoop(ln39, "30139", klFile, dataFile)
}

func acceptLoop(ln net.Listener, port string, klFile, dataFile *os.File) {
	for {
		conn, err := ln.Accept()
		if err != nil { return }
		go handleConn(conn, port, klFile, dataFile)
	}
}

func handleConn(clientConn net.Conn, port string, klFile, dataFile *os.File) {
	defer clientConn.Close()
	buf := make([]byte, 4096)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil || n < 5 { return }

	sni := parseSNI(buf[5:n])
	if sni == "" { sni = "mail.163.com" }

	cert, _ := signCert(sni)
	bc := &bufferedConn{Conn: clientConn, buf: buf[:n]}
	tlsConn := tls.Server(bc, &tls.Config{
		Certificates: []tls.Certificate{cert},
		KeyLogWriter: klFile,
	})
	if err := tlsConn.Handshake(); err != nil { return }
	defer tlsConn.Close()

	// 后端用标准TLS连接（不做MITM，直接转发）
	// 用客户端的目标地址
	clientAddr := clientConn.RemoteAddr().String()
	_ = clientAddr

	// 从SNI确定后端
	// 30138的后端是193.112.75.147:30138
	// 30139的后端是43.248.2.74:30139
	var backendAddr string
	if port == "30138" {
		backendAddr = "193.112.75.147:30138"
	} else {
		backendAddr = "43.248.2.74:30139"
	}

	rawBackend, err := net.DialTimeout("tcp", backendAddr, 10*time.Second)
	if err != nil {
		fmt.Printf("[%s] backend dial failed: %v\n", port, err)
		return
	}
	defer rawBackend.Close()

	backendConfig := &utls.Config{
		InsecureSkipVerify: true, ServerName: sni,
		MinVersion: utls.VersionTLS12, MaxVersion: utls.VersionTLS12,
	}
	backend := utls.UClient(rawBackend, backendConfig, utls.HelloCustom)
	spec := &utls.ClientHelloSpec{
		CipherSuites: []uint16{0xc00a, 0xc014, 0x0039, 0x006b, 0x0035, 0x003d,
			0xc007, 0xc009, 0xc023, 0xc011, 0xc013, 0xc027,
			0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002f, 0x003c, 0x000a},
		CompressionMethods: []byte{0x01, 0x00},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: sni},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{0x001d, 0x0017, 0x0018, 0x0019}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.SessionTicketExtension{},
			&utls.GenericExtension{Id: 0x3374},
			&utls.ALPNExtension{AlpnProtocols: []string{"spdy/2", "spdy/3", "spdy/3.1", "http/1.1"}},
			&utls.GenericExtension{Id: 0x754f},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0402, 0x0202}},
		},
	}
	if err := backend.ApplyPreset(spec); err != nil { return }
	if err := backend.Handshake(); err != nil { return }
	defer backend.Close()

	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		b := make([]byte, 16384)
		for {
			n, err := tlsConn.Read(b)
			if err != nil { break }
			mu.Lock()
			dataFile.WriteString(fmt.Sprintf("APP_%s %d %s\n", port, n, hex.EncodeToString(b[:n])))
			mu.Unlock()
			backend.Write(b[:n])
		}
	}()
	go func() {
		defer wg.Done()
		b := make([]byte, 16384)
		for {
			n, err := backend.Read(b)
			if err != nil { break }
			mu.Lock()
			dataFile.WriteString(fmt.Sprintf("SRV_%s %d %s\n", port, n, hex.EncodeToString(b[:n])))
			mu.Unlock()
			tlsConn.Write(b[:n])
		}
	}()
	wg.Wait()
}

func parseSNI(data []byte) string {
	if len(data) < 37 { return "" }
	offset := 2 + 32
	if offset >= len(data) { return "" }
	sidLen := int(data[offset])
	offset += 1 + sidLen
	if offset+1 >= len(data) { return "" }
	csLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + csLen
	if offset >= len(data) { return "" }
	compLen := int(data[offset])
	offset += 1 + compLen
	if offset+1 >= len(data) { return "" }
	extLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	extEnd := offset + extLen
	for offset+4 <= extEnd && offset+4 <= len(data) {
		extType := int(data[offset])<<8 | int(data[offset+1])
		el := int(data[offset+2])<<8 | int(data[offset+3])
		if extType == 0 && el > 5 && offset+4+el <= len(data) {
			sniLen := int(data[offset+7])<<8 | int(data[offset+8])
			if offset+9+sniLen <= len(data) {
				return string(data[offset+9 : offset+9+sniLen])
			}
		}
		offset += 4 + el
	}
	return ""
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
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, caCert, &serverKey.PublicKey, caKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})
	return tls.X509KeyPair(certPEM, keyPEM)
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
