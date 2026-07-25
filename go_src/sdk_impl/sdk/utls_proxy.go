package sdk

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// UTLSProxyServer 使用utls的代理服务器
type UTLSProxyServer struct {
	AESKey     string
	LocalPort  int
	ProxyAddr  string
	SNI        string
	DeviceUUID string

	listener   net.Listener
	authKey    []byte
	keyLogFile *os.File
	connections sync.WaitGroup
	mu          sync.Mutex
	running    bool
}

func NewUTLSProxyServer(aesKey, proxyAddr, sni, deviceUUID string, localPort int) *UTLSProxyServer {
	return &UTLSProxyServer{
		AESKey:     aesKey,
		LocalPort:  localPort,
		ProxyAddr:  proxyAddr,
		SNI:        sni,
		DeviceUUID: deviceUUID,
	}
}

// Start 启动代理
func (p *UTLSProxyServer) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("already running")
	}
	p.running = true
	p.mu.Unlock()

	// 创建keylog文件
	p.keyLogFile, _ = os.CreateTemp("", "utls-keylog-*.log")

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p.LocalPort))
	if err != nil {
		return err
	}
	p.listener = ln
	log.Printf("[utls-proxy] listening on 127.0.0.1:%d → %s (SNI=%s)", p.LocalPort, p.ProxyAddr, p.SNI)

	go p.acceptLoop()
	return nil
}

func (p *UTLSProxyServer) Stop() {
	p.mu.Lock()
	p.running = false
	p.mu.Unlock()
	if p.listener != nil {
		p.listener.Close()
	}
	if p.keyLogFile != nil {
		p.keyLogFile.Close()
	}
	p.connections.Wait()
}

func (p *UTLSProxyServer) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			p.mu.Lock()
			running := p.running
			p.mu.Unlock()
			if !running {
				return
			}
			continue
		}
		p.connections.Add(1)
		go p.handleConn(conn)
	}
}

func (p *UTLSProxyServer) handleConn(userConn net.Conn) {
	defer p.connections.Done()
	defer userConn.Close()

	// 连接到代理节点
	rawConn, err := net.DialTimeout("tcp", p.ProxyAddr, 10*time.Second)
	if err != nil {
		log.Printf("[utls-proxy] dial failed: %v", err)
		return
	}

	// utls TLS握手
	config := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         p.SNI,
		MinVersion:         utls.VersionTLS12,
		MaxVersion:         utls.VersionTLS12,
		KeyLogWriter:       p.keyLogFile,
	}

	uConn := utls.UClient(rawConn, config, utls.HelloCustom)
	spec := &utls.ClientHelloSpec{
		CipherSuites: []uint16{
			0xc00a, 0xc014, 0x0039, 0x006b, 0x0035, 0x003d,
			0xc007, 0xc009, 0xc023, 0xc011, 0xc013, 0xc027,
			0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002f,
			0x003c, 0x000a,
		},
		CompressionMethods: []byte{0x01, 0x00},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: p.SNI},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{0x001d, 0x0017, 0x0018, 0x0019}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.SessionTicketExtension{},
			&utls.GenericExtension{Id: 0x3374},
			&utls.ALPNExtension{AlpnProtocols: []string{"spdy/2", "spdy/3", "spdy/3.1", "http/1.1"}},
			&utls.GenericExtension{Id: 0x754f},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0402, 0x0202,
			}},
		},
	}

	if err := uConn.ApplyPreset(spec); err != nil {
		log.Printf("[utls-proxy] preset failed: %v", err)
		rawConn.Close()
		return
	}
	if err := uConn.Handshake(); err != nil {
		log.Printf("[utls-proxy] handshake failed: %v", err)
		rawConn.Close()
		return
	}
	defer uConn.Close()

	// 获取master_secret从keylog
	p.keyLogFile.Sync()
	keylogData, _ := os.ReadFile(p.keyLogFile.Name())
	masterSecret := p.extractMasterSecret(string(keylogData))

	if masterSecret != nil {
		p.mu.Lock()
		p.authKey = make([]byte, 256)
		copy(p.authKey, masterSecret)
		p.mu.Unlock()
		log.Printf("[utls-proxy] auth_key_id=%s", AuthKeyID(masterSecret))
	}

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	// 用户 → 代理
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := userConn.Read(buf)
			if err != nil {
				break
			}
			// MTProto加密 + DEADBEEF封装
			p.mu.Lock()
			ak := p.authKey
			p.mu.Unlock()
			if ak != nil {
				enc, err := MTProtoEncrypt(ak, buf[:n])
				if err != nil {
					break
				}
				frame := BuildDeadBEEFFrame(enc)
				uConn.Write(frame)
			} else {
				// 没有auth_key，直接转发
				uConn.Write(buf[:n])
			}
		}
		uConn.Close()
	}()

	// 代理 → 用户
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := uConn.Read(buf)
			if err != nil {
				break
			}
			// 解析DEADBEEF帧
			payload, err := parseDeadBEEFFrame(buf[:n])
			if err != nil {
				userConn.Write(buf[:n])
				continue
			}
			p.mu.Lock()
			ak := p.authKey
			p.mu.Unlock()
			if ak != nil {
				dec, err := MTProtoDecrypt(ak, payload)
				if err != nil {
					userConn.Write(payload)
				} else {
					userConn.Write(dec)
				}
			} else {
				userConn.Write(payload)
			}
		}
		userConn.Close()
	}()

	wg.Wait()
}

// extractMasterSecret 从keylog提取master_secret
func (p *UTLSProxyServer) extractMasterSecret(keylog string) []byte {
	lines := strings.Split(strings.TrimSpace(keylog), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 3 && parts[0] == "CLIENT_RANDOM" {
			ms, err := hex.DecodeString(parts[2])
			if err == nil && len(ms) == 48 {
				return ms
			}
		}
	}
	return nil
}

// SetAuthKey 手动设置auth_key
func (p *UTLSProxyServer) SetAuthKey(masterSecret []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.authKey = make([]byte, 256)
	copy(p.authKey, masterSecret)
}


var _ = rand.Reader
