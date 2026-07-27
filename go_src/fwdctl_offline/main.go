// fwdctl_offline — 纯离线获取 app_line_ips 的 forwarder control 客户端
//
// 逆向依据: reports/forwarder_control_protocol_FINAL.md
// 协议 = utls(HelloGolang 指纹) TLS1.3 + ALPN "cursor-control-v1" + 明文 JSON。
// 服务端按 TLS 指纹分流: Chrome->代理转发(h2), Go->forwarder control(cursor-control-v1)。
//
// fwdHelloRequest struct(来自Ghidra): V,Type,AppName,SDKVersion,DeviceID,LastVersion,TS,Nonce,Capabilities,MAC
// MAC = hex(HMAC-SHA256(KEY, Join(["v1","hello",AppName,SDKVersion,DeviceID,versionStr,tsStr,Nonce],"|")))
//
// 用法:
//   go run . -key <AES> -sni <SNI> -app dh139 -sdkver 4.0.1 -nodes ip:port,ip:port
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

const alpn = "cursor-control-v1"

type fwdHelloRequest struct {
	Version       int    `json:"version"`
	Type          string `json:"type"`
	AppName       string `json:"app_name"`
	SDKVersion    string `json:"sdk_version"`
	DeviceID      string `json:"device_id"`
	TimestampUnix int64  `json:"timestamp_unix"`
	Nonce         string `json:"nonce"`
	MAC           string `json:"mac"`
}

type fwdControlResponse struct {
	V                 int      `json:"version"`
	Type              string   `json:"type"`
	AppName           string   `json:"app_name,omitempty"`
	SDKVersion        string   `json:"sdk_version,omitempty"`
	Code              string   `json:"code,omitempty"`
	Message           string   `json:"message,omitempty"`
	RetryAfterSeconds int      `json:"retry_after_seconds,omitempty"`
	AppLineIPs        []string `json:"app_line_ips,omitempty"`
	AppLinePort       int      `json:"app_line_port,omitempty"`
	FixedA            string   `json:"fixedA,omitempty"`
	FixedB            string   `json:"fixedB,omitempty"`
	FixedC            string   `json:"fixedC,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`
	MAC               string   `json:"mac,omitempty"`
	Raw               string   `json:"-"`
}

func randomNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b) + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// MAC = hex(HMAC-SHA256(key, "v1|hello|AppName|SDKVersion|DeviceID|versionStr|tsStr|Nonce"))
func signMAC(key, appName, sdkVersion, deviceID, versionStr, tsStr, nonce string) string {
	msg := strings.Join([]string{
		"v1", "hello", appName, sdkVersion, deviceID, versionStr, tsStr, nonce,
	}, "|")
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

func fetch(node, key, sni, appName, sdkVersion, deviceID string) (*fwdControlResponse, error) {
	d := net.Dialer{Timeout: 8 * time.Second}
	raw, err := d.Dial("tcp", node)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	defer raw.Close()

	// 关键: 用 Go 指纹(HelloGolang)才会协商到 cursor-control-v1; Chrome 指纹会被当代理通道(h2)
	tconn := utls.UClient(raw, &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
		NextProtos:         []string{alpn},
	}, utls.HelloGolang)
	tconn.SetDeadline(time.Now().Add(12 * time.Second))
	if err := tconn.Handshake(); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	if got := tconn.ConnectionState().NegotiatedProtocol; got != alpn {
		return nil, fmt.Errorf("unexpected alpn %q", got)
	}

	ts := time.Now().Unix()
	nonce := randomNonce()
	req := fwdHelloRequest{
		Version: 0, Type: "hello", AppName: appName, SDKVersion: sdkVersion,
		DeviceID: deviceID, TimestampUnix: ts, Nonce: nonce,
	}
	// versionStr="" (LastVersion 为 nil)
	req.MAC = signMAC(key, appName, sdkVersion, deviceID, "", strconv.FormatInt(ts, 10), nonce)

	body, _ := json.Marshal(req)
	body = append(body, '\n')
	if _, err := tconn.Write(body); err != nil {
		return nil, fmt.Errorf("write hello: %w", err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadAtLeast(tconn, hdr, 4); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr)
	if n < 1 || n > 0xffff {
		return nil, fmt.Errorf("invalid payload length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadAtLeast(tconn, buf, int(n)); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	var resp fwdControlResponse
	if err := json.Unmarshal(buf, &resp); err != nil {
		return nil, fmt.Errorf("parse json: %w (raw=%s)", err, string(buf))
	}
	resp.Raw = string(buf)
	return &resp, nil
}

func main() {
	key := flag.String("key", "", "AES_key (HMAC key candidate)")
	keyb64 := flag.Bool("keyb64", false, "把 -key 当 base64 解码后作为 HMAC key 字节")
	sni := flag.String("sni", "", "伪装 SNI")
	app := flag.String("app", "", "app_name, 如 dh139")
	sdkver := flag.String("sdkver", "4.0.1", "sdk_version")
	uuid := flag.String("uuid", "", "device_id（留空随机）")
	nodesArg := flag.String("nodes", "", "逗号分隔 host:port")
	flag.Parse()
	if *key == "" || *nodesArg == "" || *app == "" {
		fmt.Println("用法: -key <AES> -sni <SNI> -app dh139 -sdkver 4.0.1 -nodes ip:port,ip:port")
		return
	}
	dev := *uuid
	if dev == "" {
		b := make([]byte, 47)
		rand.Read(b)
		dev = hex.EncodeToString(b)[:94]
	}
	effKey := *key
	if *keyb64 {
		raw, err := base64.StdEncoding.DecodeString(*key)
		if err != nil {
			fmt.Println("base64 decode key failed:", err)
			return
		}
		effKey = string(raw)
	}
	for _, node := range strings.Split(*nodesArg, ",") {
		node = strings.TrimSpace(node)
		if node == "" {
			continue
		}
		resp, err := fetch(node, effKey, *sni, *app, *sdkver, dev)
		if err != nil {
			fmt.Printf("[-] %s : %v\n", node, err)
			continue
		}
		if len(resp.AppLineIPs) > 0 {
			fmt.Printf("[+] %s : ✅ 成功! port=%d, %d 个 app_line_ips:\n", node, resp.AppLinePort, len(resp.AppLineIPs))
			for _, ip := range resp.AppLineIPs {
				fmt.Printf("      %s\n", ip)
			}
			return
		}
		fmt.Printf("[?] %s : 响应但无节点: %s\n", node, resp.Raw)
	}
}
