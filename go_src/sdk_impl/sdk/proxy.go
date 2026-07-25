package sdk

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// ProxyServer VPN代理服务器
type ProxyServer struct {
	AESKey      string
	LocalPort   int // 60139
	ProxyAddr   string // 8.134.180.186:30139
	SNI         string
	DeviceUUID  string

	listener   net.Listener
	authKey    []byte // master_secret
	connections sync.WaitGroup
	mu          sync.Mutex
	running     bool
}

// NewProxyServer 创建代理服务器
func NewProxyServer(aesKey, proxyAddr, sni, deviceUUID string, localPort int) *ProxyServer {
	return &ProxyServer{
		AESKey:     aesKey,
		LocalPort:  localPort,
		ProxyAddr:  proxyAddr,
		SNI:        sni,
		DeviceUUID: deviceUUID,
	}
}

// Start 启动代理服务器
func (p *ProxyServer) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("already running")
	}
	p.running = true
	p.mu.Unlock()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p.LocalPort))
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	p.listener = ln
	log.Printf("[proxy] listening on 127.0.0.1:%d → %s", p.LocalPort, p.ProxyAddr)

	go p.acceptLoop()
	return nil
}

// Stop 停止代理服务器
func (p *ProxyServer) Stop() {
	p.mu.Lock()
	p.running = false
	p.mu.Unlock()
	if p.listener != nil {
		p.listener.Close()
	}
	p.connections.Wait()
}

func (p *ProxyServer) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			p.mu.Lock()
			running := p.running
			p.mu.Unlock()
			if !running {
				return
			}
			log.Printf("[proxy] accept error: %v", err)
			continue
		}
		p.connections.Add(1)
		go p.handleConn(conn)
	}
}

// handleConn 处理用户连接
// 1. 接受用户TCP连接
// 2. 建立到代理节点的TLS连接
// 3. TLS握手获取master_secret → auth_key
// 4. 用户数据 → DEADBEEF+MTProto封装 → TLS发送到代理节点
// 5. 代理节点响应 → TLS接收 → DEADBEEF解析 → MTProto解密 → 发回用户
func (p *ProxyServer) handleConn(userConn net.Conn) {
	defer p.connections.Done()
	defer userConn.Close()

	// 连接到代理节点
	proxyConn, err := tls.Dial("tcp", p.ProxyAddr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         p.SNI,
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
		log.Printf("[proxy] TLS dial failed: %v", err)
		return
	}
	defer proxyConn.Close()

	// 获取master_secret作为auth_key
	// 注意：标准crypto/tls不暴露master_secret
	// 在实际APK中用utls+KeyLogWriter获取
	// 这里用TLS连接状态作为简化
	state := proxyConn.ConnectionState()
	_ = state // 实际需要master_secret

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	// 用户 → 代理（封装）
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := userConn.Read(buf)
			if err != nil {
				break
			}
			// 封装为DEADBEEF+MTProto
			encData, err := MTProtoEncrypt(p.authKey, buf[:n])
			if err != nil {
				break
			}
			frame := BuildDeadBEEFFrame(encData)
			if _, err := proxyConn.Write(frame); err != nil {
				break
			}
		}
	}()

	// 代理 → 用户（解封装）
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := proxyConn.Read(buf)
			if err != nil {
				break
			}
			// 解析DEADBEEF帧
			payload, err := parseDeadBEEFFrame(buf[:n])
			if err != nil {
				// 可能不是DEADBEEF格式，直接转发
				userConn.Write(buf[:n])
				continue
			}
			// MTProto解密
			decData, err := MTProtoDecrypt(p.authKey, payload)
			if err != nil {
				// 可能未加密，直接转发
				userConn.Write(payload)
				continue
			}
			userConn.Write(decData)
		}
	}()

	wg.Wait()
}

// parseDeadBEEFFrame 解析DEADBEEF帧
func parseDeadBEEFFrame(data []byte) ([]byte, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("too short")
	}
	if data[0] != 0xDE || data[1] != 0xAD || data[2] != 0xBE || data[3] != 0xEF {
		return nil, fmt.Errorf("bad magic")
	}
	// sublen(2B) + payload_len(2B) + padding_len(1B) + padding + payload
	payloadLen := int(binary.BigEndian.Uint16(data[6:8]))
	paddingLen := int(data[8])
	if len(data) < 9+paddingLen+payloadLen {
		return nil, fmt.Errorf("incomplete frame")
	}
	payload := data[9+paddingLen : 9+paddingLen+payloadLen]
	return payload, nil
}

// SetAuthKey 设置auth_key（从TLS master_secret获取）
func (p *ProxyServer) SetAuthKey(masterSecret []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// auth_key = master_secret 补零到256字节
	p.authKey = make([]byte, 256)
	copy(p.authKey, masterSecret)
}

// GenerateDeviceUUID 生成设备UUID
func GenerateDeviceUUID() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return fmt.Sprintf("%x%d", buf, time.Now().UnixNano())
}

// StateMachine 状态机
type StateMachine struct {
	state    string // "idle" → "preparing" → "running" → "route_ready"
	mu       sync.Mutex
}

func NewStateMachine() *StateMachine {
	return &StateMachine{state: "idle"}
}

func (sm *StateMachine) State() string {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.state
}

func (sm *StateMachine) SetState(s string) {
	sm.mu.Lock()
	sm.state = s
	sm.mu.Unlock()
}

// HealthChecker 健康检查器
type HealthChecker struct {
	nodes    []string
	interval time.Duration
	stopCh   chan struct{}
}

func NewHealthChecker(nodes []string, interval time.Duration) *HealthChecker {
	return &HealthChecker{
		nodes:    nodes,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (hc *HealthChecker) Start() {
	go func() {
		ticker := time.NewTicker(hc.interval)
		defer ticker.Stop()
		for {
			select {
			case <-hc.stopCh:
				return
			case <-ticker.C:
				for _, node := range hc.nodes {
					go hc.checkNode(node)
				}
			}
		}
	}()
}

func (hc *HealthChecker) Stop() {
	close(hc.stopCh)
}

func (hc *HealthChecker) checkNode(addr string) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		log.Printf("[health] %s: FAIL", addr)
		return
	}
	conn.Close()
	log.Printf("[health] %s: OK", addr)
}

// FailoverManager 故障转移管理器
type FailoverManager struct {
	primary  string
	fallback []string
	current  string
	mu       sync.Mutex
}

func NewFailoverManager(primary string, fallback []string) *FailoverManager {
	return &FailoverManager{
		primary:  primary,
		fallback: fallback,
		current:  primary,
	}
}

func (fm *FailoverManager) Current() string {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	return fm.current
}

func (fm *FailoverManager) Failover() string {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	for _, node := range fm.fallback {
		if node != fm.current {
			conn, err := net.DialTimeout("tcp", node, 3*time.Second)
			if err == nil {
				conn.Close()
				fm.current = node
				log.Printf("[failover] switched to %s", node)
				return node
			}
		}
	}
	return fm.current
}

var _ = io.Copy // ensure io import used
var _ = log.Printf
