package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
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

	tlsinternal "crypto/tls"
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

	dataFile, _ := os.Create("/sdcard/prems2_data.txt")
	defer dataFile.Close()

	ln38, _ := net.Listen("tcp", "127.0.0.1:30138")
	ln39, _ := net.Listen("tcp", "127.0.0.1:30139")
	fmt.Println("PreMS2 proxy started")

	go acceptLoop(ln38, "30138", dataFile)
	acceptLoop(ln39, "30139", dataFile)
}

func acceptLoop(ln net.Listener, port string, dataFile *os.File) {
	for {
		conn, err := ln.Accept()
		if err != nil { return }
		go handleConn(conn, port, dataFile)
	}
}

func handleConn(clientConn net.Conn, port string, dataFile *os.File) {
	defer clientConn.Close()
	buf := make([]byte, 4096)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := clientConn.Read(buf)
	if err != nil || n < 5 { return }

	sni := parseSNI(buf[5:n])
	if sni == "" { sni = "mail.163.com" }

	cert, _ := signCert(sni)
	bc := &bufferedConn{Conn: clientConn, buf: buf[:n]}
	serverConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConn := tls.Server(bc, serverConfig)
	if err := tlsConn.Handshake(); err != nil { return }
	defer tlsConn.Close()

	// 服务端preMasterSecret (APP→代理)
	serverPreMS := tlsinternal.SavedPreMasterSecret
	if serverPreMS != nil {
		h := sha1.Sum(serverPreMS)
		dataFile.WriteString(fmt.Sprintf("SPREMS %s %d %s %s\n", port, len(serverPreMS), hex.EncodeToString(serverPreMS), hex.EncodeToString(h[:8])))
	}

	// Backend
	var backendAddr string
	if port == "30138" {
		backendAddr = "193.112.75.147:30138"
	} else {
		backendAddr = "43.248.2.74:30139"
	}

	rawBackend, err := net.DialTimeout("tcp", backendAddr, 10*time.Second)
	if err != nil { return }
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

	// 客户端preMasterSecret (代理→后端)
	clientPreMS := tlsinternal.SavedPreMasterSecretClient
	if clientPreMS != nil {
		h := sha1.Sum(clientPreMS)
		dataFile.WriteString(fmt.Sprintf("CPREMS %s %d %s %s\n", port, len(clientPreMS), hex.EncodeToString(clientPreMS), hex.EncodeToString(h[:8])))
	}

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
			if b[0] == 0xDE && n > 9 {
				padLen := int(b[8])
				innerStart := 9 + padLen
				if innerStart+8 <= n {
					akid := hex.EncodeToString(b[innerStart : innerStart+8])
					mu.Lock()
					dataFile.WriteString(fmt.Sprintf("AKID_%s %s\n", port, akid))
					mu.Unlock()
					// 匹配
					for _, preMS := range [][]byte{serverPreMS, clientPreMS} {
						if preMS == nil { continue }
						// SHA1(preMS)
						h := sha1.Sum(preMS)
						eid := hex.EncodeToString(h[:8])
						if eid == akid {
							mu.Lock()
							dataFile.WriteString(fmt.Sprintf("MATCH! SHA1(preMS)[:8]=%s\n", eid))
							mu.Unlock()
						}
						// preMS+zeros
						ak := make([]byte, 256)
						copy(ak, preMS)
						h2 := sha1.Sum(ak)
						eid2 := hex.EncodeToString(h2[:8])
						if eid2 == akid {
							mu.Lock()
							dataFile.WriteString(fmt.Sprintf("MATCH! SHA1(preMS+zeros)[:8]=%s\n", eid2))
							mu.Unlock()
						}
						// preMS[:8]
						eid3 := hex.EncodeToString(preMS[:8])
						if eid3 == akid {
							mu.Lock()
							dataFile.WriteString(fmt.Sprintf("MATCH! preMS[:8]=%s\n", eid3))
							mu.Unlock()
						}
					}
				}
			}
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
