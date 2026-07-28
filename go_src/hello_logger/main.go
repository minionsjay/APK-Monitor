// hello_logger — 透明 MITM,只截 forwarder control(ALPN cursor-control-v1),抓明文 hello。
// 代理转发连接(spdy/h2/http)原样 TCP 转发,保证 app 正常 bootstrap。
// iptables REDIRECT :30151 → :9999。用 SO_ORIGINAL_DST 取真实目的地。
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const SO_ORIGINAL_DST = 80

func origDst(c *net.TCPConn) (string, error) {
	f, err := c.File()
	if err != nil {
		return "", err
	}
	defer f.Close()
	var addr syscall.RawSockaddrInet4
	sz := uint32(unsafe.Sizeof(addr))
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, f.Fd(), syscall.IPPROTO_IP, SO_ORIGINAL_DST,
		uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&sz)), 0)
	if e != 0 {
		return "", e
	}
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:])
	return fmt.Sprintf("%s:%d", ip, port), nil
}

var out *os.File

func genCert() tls.Certificate {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sdk"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"www.bootcdn.cn"}}
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func rawRelay(a, b net.Conn) {
	go io.Copy(a, b)
	io.Copy(b, a)
}

func handle(cli *net.TCPConn) {
	defer cli.Close()
	dst, err := origDst(cli)
	if err != nil {
		return
	}
	// 精确读第一个 TLS record(ClientHello),避免 Peek 阻塞
	cli.SetReadDeadline(time.Now().Add(10 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(cli, hdr); err != nil {
		return
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen <= 0 || recLen > 16384 {
		return
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(cli, body); err != nil {
		return
	}
	cli.SetReadDeadline(time.Time{})
	first := append(append([]byte{}, hdr...), body...)
	pc := &prefixConn{Conn: cli, r: io.MultiReader(bytes.NewReader(first), cli)}

	hasCursor := bytes.Contains(first, []byte("cursor-control-v1"))
	// 提取ClientHello里的ALPN明文(可读子串)做诊断
	fmt.Fprintf(out, "CONN dst=%s cursor=%v rec=%dB head=%x alpnhint=%q\n",
		dst, hasCursor, len(first), first[:min(16, len(first))], grepAscii(first))
	out.Sync()

	if !hasCursor {
		// 代理转发连接 → 原样TCP转发到真实目的地
		up, err := net.DialTimeout("tcp", dst, 8*time.Second)
		if err != nil {
			return
		}
		defer up.Close()
		rawRelay(pc, up)
		return
	}

	// forwarder control → TLS 终止,抓 hello,再转发到真实服务器
	srv := tls.Server(pc, &tls.Config{Certificates: []tls.Certificate{genCert()},
		NextProtos: []string{"cursor-control-v1"}, MinVersion: tls.VersionTLS12})
	srv.SetDeadline(time.Now().Add(15 * time.Second))
	if err := srv.Handshake(); err != nil {
		fmt.Fprintln(out, "srv hs err:", err)
		return
	}
	buf := make([]byte, 8192)
	n, _ := srv.Read(buf)
	if n > 0 {
		fmt.Fprintf(out, "\n=== HELLO CAPTURED %s dst=%s ===\n%s\nHEX:%x\n", time.Now(), dst, string(buf[:n]), buf[:n])
		out.Sync()
	}
	// 转发到真实服务器(标准crypto/tls + ALPN),把响应回给app,保持正常
	up, err := tls.Dial("tcp", dst, &tls.Config{InsecureSkipVerify: true, ServerName: "www.bootcdn.cn", NextProtos: []string{"cursor-control-v1"}})
	if err != nil {
		return
	}
	defer up.Close()
	up.Write(buf[:n])
	go io.Copy(srv, up)
	io.Copy(up, srv)
}

func main() {
	out, _ = os.OpenFile("/data/local/tmp/hello_capture.txt", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	defer out.Close()
	ln, err := net.Listen("tcp", "0.0.0.0:9999")
	if err != nil {
		fmt.Fprintln(out, "listen err:", err)
		return
	}
	fmt.Fprintln(out, "transparent MITM listening 9999", time.Now())
	out.Sync()
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c.(*net.TCPConn))
	}
}

func min(a, b int) int { if a < b { return a }; return b }
func grepAscii(b []byte) string {
	var r []byte
	for _, c := range b {
		if c >= 0x20 && c < 0x7f { r = append(r, c) } else if len(r) > 0 && r[len(r)-1] != ' ' { r = append(r, ' ') }
	}
	s := string(r)
	if len(s) > 200 { s = s[:200] }
	return s
}
