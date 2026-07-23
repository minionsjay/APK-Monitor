package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

const serverPublicKeyPEM = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAvKLEOWTzt9Hn3/9Kdp/RdHcEhzmd8xXeLSpHIIzaXTLJDw8BhJy1
jR/iqeG8Je5yrtVabqMSkA6ltIpgylH///FojMsX1BHu4EPYOXQgB0qOi6kr08iX
ZIH9/iOPQOWDsL+Lt8gDG0xBy+sPe/2ZHdzKMjX6O9B4sOsxjFrk5qDoWDrioJor
AJ7eFAfPpOBf2w73ohXudSrJE0lbQ8pCWNpMY8cB9i8r+WBitcvouLDAvmtnTX7a
khoDzmKgpJBYliAY4qA73v7u5UIepE8QgV0jCOhxJCPubP8dg+/PlLLVKyxU5Cdi
QtZj2EMy4s9xlNKzX8XezE0MHEa6bQpnFwIDAQAB
-----END RSA PUBLIC KEY-----`

func main() {
	fmt.Println("=== MTProto 握手测试 ===")

	// 加载 RSA 公钥
	block, _ := pem.Decode([]byte(serverPublicKeyPEM))
	if block == nil {
		fmt.Println("PEM 解析失败")
		os.Exit(1)
	}
	pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		fmt.Println("RSA 公钥解析失败:", err)
		os.Exit(1)
	}
	fmt.Printf("RSA 公钥: N=%d bits, E=%d\n", pubKey.N.BitLen(), pubKey.E)

	// 计算 fingerprint
	pubKeyBytes := block.Bytes
	fingerprint := sha1Fingerprint(pubKeyBytes)
	fmt.Printf("Fingerprint: %s\n", fingerprint)

	// 连接控制面节点
	node := "8.138.97.66:30151"
	fmt.Printf("\n连接 %s (SNI=www.bootcdn.cn, 360Browser)...\n", node)

	conn, err := net.DialTimeout("tcp", node, 10*time.Second)
	if err != nil {
		fmt.Println("TCP 失败:", err)
		os.Exit(1)
	}

	tlsConfig := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         "www.bootcdn.cn",
	}
	uConn := utls.UClient(conn, tlsConfig, utls.Hello360_Auto)
	if err := uConn.Handshake(); err != nil {
		fmt.Println("uTLS 失败:", err)
		os.Exit(1)
	}
	fmt.Println("uTLS 握手成功")

	// 发送 req_pq_multi（通过 obfs 层）
	// MTProto req_pq_multi 格式:
	// [0:4] constructor_id = 0xbe7e8ef1 (LE)
	// [4:20] nonce (16 bytes)

	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 1) // 固定 nonce 便于调试
	}

	reqData := make([]byte, 20)
	reqData[0] = 0xf1 // 0xbe7e8ef1 LE
	reqData[1] = 0x8e
	reqData[2] = 0x7e
	reqData[3] = 0xbe
	copy(reqData[4:], nonce)

	fmt.Printf("发送 req_pq_multi (%d bytes): %s\n", len(reqData), hexEncode(reqData))

	// 通过 obfs 发送
	// 尝试多种 MTProto transport 格式
	formats := []struct {
		name string
		data []byte
	}{
		{"raw", reqData},
		{"abridged", append([]byte{byte(len(reqData) / 4)}, reqData...)},
		{"intermediate_magic", append([]byte{0xee, 0xee, 0xee, 0xee}, append([]byte{byte(len(reqData)), 0, 0, 0}, reqData...)...)},
		{"intermediate_len", append([]byte{byte(len(reqData)), 0, 0, 0}, reqData...)},
	}
	for _, fr := range formats {
		fmt.Printf("  尝试 %s (%d bytes): %s...\n", fr.name, len(fr.data), hexEncode(fr.data[:min(10, len(fr.data))]))
		_, err = uConn.Write(fr.data)
		if err != nil {
			fmt.Printf("    写入失败: %v\n", err)
			continue
		}
		uConn.SetDeadline(time.Now().Add(8 * time.Second))
		buf := make([]byte, 4096)
		n, err := uConn.Read(buf)
		if err != nil {
			fmt.Printf("    读取失败: %v\n", err)
			// 重新连接
			conn2, _ := net.DialTimeout("tcp", "8.138.97.66:30151", 10*time.Second)
			uConn = utls.UClient(conn2, tlsConfig, utls.Hello360_Auto)
			uConn.Handshake()
			continue
		}
		fmt.Printf("    ✅ 收到 %d bytes: %s\n", n, hexEncode(buf[:n])[:min(60, n)])
		if n >= 4 {
			cid := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
			fmt.Printf("    constructor: 0x%08x\n", cid)
			if cid == 0x05162463 {
				fmt.Println("    ✅✅✅ resPQ! MTProto 握手成功!")
				return
			}
		}
	}

	// 读取响应
	uConn.SetDeadline(time.Now().Add(15 * time.Second))
	// 直接读取
	respData, err := readRaw(uConn)
	if err != nil {
		fmt.Println("读取失败:", err)
		// 尝试读取原始数据
		buf := make([]byte, 1024)
		n, _ := uConn.Read(buf)
		if n > 0 {
			fmt.Printf("原始数据 (%d bytes): %s\n", n, hexEncode(buf[:n]))
			fmt.Printf("ASCII: %s\n", string(buf[:n])[:min(n, 80)])
		}
		os.Exit(1)
	}

	fmt.Printf("收到响应 (%d bytes): %s\n", len(respData), hexEncode(respData[:min(40, len(respData))]))

	// 解析 resPQ
	if len(respData) >= 4 {
		cid := uint32(respData[0]) | uint32(respData[1])<<8 | uint32(respData[2])<<16 | uint32(respData[3])<<24
		fmt.Printf("Constructor ID: 0x%08x\n", cid)
		if cid == 0x05162463 {
			fmt.Println("✅ 是 resPQ!")
		}
	}

	_ = pubKey
	_ = big.NewInt
}

// obfsWrite: DEADBEEF + padding + payload
func obfsWrite(conn net.Conn, payload []byte) error {
	padLenByte := make([]byte, 1)
	// 固定 padding 便于调试
	padLenByte[0] = 0x08 // padding_len = 8
	padLen := 8
	padding := make([]byte, padLen)
	for i := range padding {
		padding[i] = byte(i)
	}

	sublen := uint16(1 + padLen + len(payload))
	frame := make([]byte, 0, 8+int(sublen))
	// DEADBEEF (大端)
	frame = append(frame, 0xde, 0xad, 0xbe, 0xef)
	// reserved
	frame = append(frame, 0x00, 0x00)
	// sublen (大端)
	frame = append(frame, byte(sublen>>8), byte(sublen))
	// padding_len_byte
	frame = append(frame, padLenByte[0])
	// padding
	frame = append(frame, padding...)
	// payload
	frame = append(frame, payload...)

	_, err := conn.Write(frame)
	return err
}

// obfsRead: 读取 DEADBEEF 帧
func obfsRead(conn net.Conn) ([]byte, error) {
	header := make([]byte, 8)
	_, err := readFull(conn, header)
	if err != nil {
		return nil, err
	}

	if header[0] != 0xde || header[1] != 0xad || header[2] != 0xbe || header[3] != 0xef {
		return nil, fmt.Errorf("not DEADBEEF: %s", hexEncode(header[:4]))
	}

	sublen := uint16(header[6])<<8 | uint16(header[7])
	subdata := make([]byte, sublen)
	_, err = readFull(conn, subdata)
	if err != nil {
		return nil, err
	}

	// 去掉 padding
	if len(subdata) < 1 {
		return nil, fmt.Errorf("subdata too short")
	}
	padLen := int(subdata[0] & 0x3f)
	if 1+padLen > len(subdata) {
		return subdata, nil // 返回原始数据
	}
	return subdata[1+padLen:], nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func writeRaw(conn net.Conn, data []byte) error {
	_, err := conn.Write(data)
	return err
}

func readRaw(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func sha1Fingerprint(data []byte) string {
	// SHA1 of DER public key, take last 8 bytes, LE
	// 这是 MTProto 的 fingerprint 计算
	// SHA1(public_key_der) → 取后 8 字节 → 大端
	// 
	// 但这里只是显示用，不需要精确
	return "todo"
}

func hexEncode(data []byte) string {
	const hexd = "0123456789abcdef"
	s := make([]byte, len(data)*2)
	for i, b := range data {
		s[i*2] = hexd[b>>4]
		s[i*2+1] = hexd[b&0xf]
	}
	return string(s)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
