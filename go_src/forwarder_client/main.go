package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

type FwdHelloRequest struct {
	Version      string `json:"version"`
	Type         string `json:"type"`
	Nonce        string `json:"nonce"`
	DeviceUUID   string `json:"device_uuid,omitempty"`
	TimestampUnix string `json:"timestamp_unix"`
	SDKVersion   string `json:"sdk_version,omitempty"`
	MAC          string `json:"mac"`
}

// 自定义空扩展
type CustomExtension struct {
	utls.TLSExtension
	TypeID uint16
	Data   []byte
}

func (e *CustomExtension) writeToUConn(uc *utls.UConn) error {
	return nil
}

func (e *CustomExtension) Len() int {
	return 4 + len(e.Data)
}

func (e *CustomExtension) Read(b []byte) (int, error) {
	// 写入扩展类型(2B) + 长度(2B) + 数据
	if len(b) < 4 {
		return 0, fmt.Errorf("buffer too small")
	}
	b[0] = byte(e.TypeID >> 8)
	b[1] = byte(e.TypeID)
	b[2] = byte(len(e.Data) >> 8)
	b[3] = byte(len(e.Data))
	n := copy(b[4:], e.Data)
	return 4 + n, nil
}

func main() {
	aesKey := "htHtoU17cKxTjwVh1m2iyHfEI39RG1Cw"
	deviceUUID := "740176FFFFFFEEFFFFFFF8FFFFFFB8FFFFFFF414FFFFFFA561FFFFFFA66A52FFFFFFADFFFFFF9B7E544861FFFFFFAD"
	nonce := randomNonce()
	tsStr := strconv.FormatInt(time.Now().Unix(), 10)
	msg := strings.Join([]string{"2", "hello", nonce, deviceUUID, tsStr, "2", "", ""}, ".")
	mac := hmacHex(aesKey, msg)

	req := FwdHelloRequest{
		Version: "2", Type: "hello", Nonce: nonce,
		DeviceUUID: deviceUUID, TimestampUnix: tsStr,
		SDKVersion: "4.0.1", MAC: mac,
	}
	jsonData, _ := json.Marshal(req)
	fmt.Printf("JSON: %s\n\n", jsonData)

	node := "8.138.152.138:30139"

	// 用utls自定义ClientHelloSpec
	// 完全模拟APP的ClientHello
	fmt.Printf("=== utls自定义扩展(0x3374+0x754f) ===\n")
	sendWithCustomExt(node, "mail.163.com", jsonData)
}

func sendWithCustomExt(node, sni string, data []byte) {
	rawConn, err := net.DialTimeout("tcp", node, 10*time.Second)
	if err != nil {
		fmt.Printf("连接失败: %v\n", err)
		return
	}
	defer rawConn.Close()

	config := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
		MinVersion:         utls.VersionTLS12,
		MaxVersion:         utls.VersionTLS12,
	}

	uConn := utls.UClient(rawConn, config, utls.HelloCustom)

	// 完全模拟APP的ClientHello
	spec := &utls.ClientHelloSpec{
		CipherSuites: []uint16{
			0xc00a, 0xc014, 0x0039, 0x006b, 0x0035, 0x003d,
			0xc007, 0xc009, 0xc023, 0xc011, 0xc013, 0xc027,
			0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002f,
			0x003c, 0x000a,
		},
		CompressionMethods: []byte{0x01, 0x00}, // DEFLATE + NULL
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: sni},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{0x001d, 0x0017, 0x0018, 0x0019}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.SessionTicketExtension{},
			// 自定义扩展0x3374 (空)
			&utls.GenericExtension{Id: 0x3374},
			// ALPN
			&utls.ALPNExtension{AlpnProtocols: []string{"spdy/2", "spdy/3", "spdy/3.1", "http/1.1"}},
			// 自定义扩展0x754f (空)
			&utls.GenericExtension{Id: 0x754f},
			&utls.SCTExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203,
				0x0402, 0x0202,
			}},
		},
	}

	if err := uConn.ApplyPreset(spec); err != nil {
		fmt.Printf("ApplyPreset失败: %v\n", err)
		return
	}

	if err := uConn.Handshake(); err != nil {
		fmt.Printf("TLS握手失败: %v\n", err)
		return
	}
	defer uConn.Close()

	state := uConn.ConnectionState()
	fmt.Printf("TLS成功! cipher=0x%04x version=0x%04x\n", state.CipherSuite, state.Version)

	uConn.SetDeadline(time.Now().Add(5 * time.Second))
	uConn.Write(data)

	buf := make([]byte, 8192)
	n, err := uConn.Read(buf)
	if err != nil {
		fmt.Printf("读取: %v\n", err)
		return
	}
	s := string(buf[:n])
	if len(s) > 200 {
		s = s[:200]
	}
	fmt.Printf("收到 %d: %s\n", n, s)
}

func randomNonce() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf) + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func hmacHex(key, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
