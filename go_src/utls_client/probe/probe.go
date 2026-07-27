// utls 分层探针：判断控制节点公网端口到底认什么 TLS 指纹 + 什么 ALPN
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

func try(node, sni, alpn string, id utls.ClientHelloID, label string) {
	raw, err := net.DialTimeout("tcp", node, 6*time.Second)
	if err != nil {
		fmt.Printf("  [%s] TCP fail: %v\n", label, err)
		return
	}
	defer raw.Close()
	cfg := &utls.Config{InsecureSkipVerify: true, ServerName: sni}
	if alpn != "" {
		cfg.NextProtos = []string{alpn}
	}
	c := utls.UClient(raw, cfg, id)
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if err := c.Handshake(); err != nil {
		fmt.Printf("  [%s] handshake fail: %v\n", label, err)
		return
	}
	st := c.ConnectionState()
	fmt.Printf("  [%s] HANDSHAKE OK  ver=0x%x cipher=0x%x alpn=%q\n", label, st.Version, st.CipherSuite, st.NegotiatedProtocol)
}

func main() {
	node := os.Args[1]
	sni := os.Args[2]
	alpn := "cursor-control-v1"
	fmt.Printf("=== probe %s (sni=%s, alpn=%s) ===\n", node, sni, alpn)
	try(node, sni, alpn, utls.HelloChrome_115_PQ, "Chrome115_PQ +alpn")
	try(node, sni, alpn, utls.HelloChrome_120, "Chrome120 +alpn")
	try(node, sni, "", utls.HelloChrome_120, "Chrome120 noalpn")
	try(node, sni, alpn, utls.HelloGolang, "Golang +alpn")
	try(node, sni, alpn, utls.HelloChrome_Auto, "ChromeAuto +alpn")
}
