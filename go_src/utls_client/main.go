package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	PSK = ""
	PORT = 30052
)

type FwdHelloRequest struct {
	Nonce      string `json:"nonce"`
	MAC        string `json:"mac"`
	DeviceUUID string `json:"device_uuid"`
	Version    string `json:"version"`
	SDKVersion string `json:"sdk_version"`
	AppName    string `json:"app_name"`
}

type FwdControlResponse struct {
	Nonce       string   `json:"nonce,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	AppLineIPs  []string `json:"app_line_ips,omitempty"`
	AppLinePort int      `json:"app_line_port,omitempty"`
	FixedSet    interface{} `json:"fixed_set,omitempty"`
}

func hmacSHA256Hex(key, msg string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(msg))
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	controlNodes := []string{"43.248.2.74", "110.41.82.109", "129.204.151.112"}

	fmt.Println("=== exdyfb forwarder control v3 (DEADBEEF + plain JSON) ===")

	for _, node := range controlNodes {
		fmt.Printf("\n--- %s ---\n", node)
		err := connectNode(node)
		if err != nil {
			fmt.Printf("失败: %v\n", err)
		} else {
			break
		}
	}
}

func connectNode(nodeIP string) error {
	addr := fmt.Sprintf("%s:%d", nodeIP, PORT)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("TCP: %v", err)
	}

	// uTLS with Chrome fingerprint
	tlsConfig := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         "sdk.3jw0c.com",
	}
	uConn := utls.UClient(conn, tlsConfig, utls.HelloChrome_Auto)
	err = uConn.Handshake()
	if err != nil {
		conn.Close()
		return fmt.Errorf("TLS: %v", err)
	}
	fmt.Println("TLS OK")

	// Generate nonce: randomForwarderNonce = 16 bytes random, hex encoded
	nonceBytes := make([]byte, 16)
	rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)
	// signForwarderHelloMAC: HMAC(PSK, "hello" + nonce_hex)
	mac := hmacSHA256Hex(PSK, "hello"+nonce)

	// Build JSON request with all fields
	req := FwdHelloRequest{
		Nonce:      nonce,
		MAC:        mac,
		DeviceUUID: "740176FFFFFFEEFFFFFFF8FFFFFFB8FFFFFFF414FFFFFFA561FFFFFFA66A52FFFFFFADFFFFFF9B7E544861FFFFFFAD",
		Version:    "0",
		SDKVersion: "4.0.1",
		AppName:    "dh052",
	}
	reqJSON, _ := json.Marshal(req)
	fmt.Printf("JSON (%d): %s\n", len(reqJSON), string(reqJSON))

	// Build DEADBEEF packet: magic(4) + 0x0000(2) + len(2) + JSON
	pkt := make([]byte, 8+len(reqJSON))
	binary.BigEndian.PutUint32(pkt[0:4], 0xDEADBEEF)
	binary.BigEndian.PutUint16(pkt[4:6], 0x0000)
	binary.BigEndian.PutUint16(pkt[6:8], uint16(len(reqJSON)))
	copy(pkt[8:], reqJSON)

	fmt.Printf("Sending DEADBEEF (%d bytes): %x...\n", len(pkt), pkt[:16])
	_, err = uConn.Write(pkt)
	if err != nil {
		conn.Close()
		return fmt.Errorf("write: %v", err)
	}

	// Read response with io.ReadAtLeast
	// First read 8 bytes (DEADBEEF header)
	uConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	header := make([]byte, 8)
	_, err = io.ReadAtLeast(uConn, header, 8)
	if err != nil {
		conn.Close()
		return fmt.Errorf("read header: %v", err)
	}
	fmt.Printf("Response header: %x\n", header)

	magic := binary.BigEndian.Uint32(header[0:4])
	if magic == 0xDEADBEEF {
		respLen := binary.BigEndian.Uint16(header[6:8])
		fmt.Printf("DEADBEEF! respLen=%d\n", respLen)
		if respLen > 0 && respLen < 16000 {
			body := make([]byte, respLen)
			_, err = io.ReadAtLeast(uConn, body, int(respLen))
			if err != nil {
				conn.Close()
				return fmt.Errorf("read body: %v", err)
			}
			fmt.Printf("Body (%d): %s\n", len(body), string(body[:min(len(body), 500)]))

			var resp FwdControlResponse
			if json.Unmarshal(body, &resp) == nil && len(resp.AppLineIPs) > 0 {
				fmt.Printf("\n✅ PROXY NODES (%d):\n", len(resp.AppLineIPs))
				for _, ip := range resp.AppLineIPs {
					fmt.Printf("  %s:%d\n", ip, resp.AppLinePort)
				}
				os.WriteFile("/home/ninini/Agents/APK-Research/proxy_nodes_offline.json", body, 0644)
			}
		}
	} else {
		// Not DEADBEEF, read more
		rest := make([]byte, 4096)
		n, _ := uConn.Read(rest)
		fullResp := append(header, rest[:n]...)
		fmt.Printf("Non-DEADBEEF (%d): %s\n", len(fullResp), string(fullResp[:min(len(fullResp), 200)]))
	}

	conn.Close()
	return nil
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
