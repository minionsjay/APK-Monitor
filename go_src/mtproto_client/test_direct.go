package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

func main() {
	server := "8.138.152.138:30139"
	sni := "mail.163.com"

	conn, err := tls.Dial("tcp", server, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
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
		fmt.Println("TLS连接失败:", err)
		return
	}
	defer conn.Close()
	fmt.Println("✅ TLS握手成功!")

	// 直接发送未加密的MTProto req_pq_multi
	// 不经过DEADBEEF wrapper
	// 标准MTProto格式: auth_key_id(8B=0) + msg_id(8B) + msg_len(4B) + constructor(4B) + nonce(16B)
	nonce := make([]byte, 16)
	for i := range nonce { nonce[i] = byte(i + 1) }
	
	msg := make([]byte, 40)
	binary.LittleEndian.PutUint64(msg[0:8], 0) // auth_key_id = 0 (未加密)
	msg_id := uint64(time.Now().Unix()) << 32
	binary.LittleEndian.PutUint64(msg[8:16], msg_id)
	binary.LittleEndian.PutUint32(msg[16:20], 20) // msg_len
	binary.LittleEndian.PutUint32(msg[20:24], 0xbe7e8720) // req_pq_multi constructor
	copy(msg[24:40], nonce)

	fmt.Printf("发送req_pq_multi: %s\n", hex.EncodeToString(msg))
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	conn.Write(msg)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("读取失败: %v\n", err)
	} else {
		fmt.Printf("✅ 收到 %d 字节: %s\n", n, hex.EncodeToString(buf[:n]))
		// 检查是否是resPQ
		if n >= 24 {
			resp_auth_key_id := binary.LittleEndian.Uint64(buf[0:8])
			resp_msg_id := binary.LittleEndian.Uint64(buf[8:16])
			resp_msg_len := binary.LittleEndian.Uint32(buf[16:20])
			constructor := binary.LittleEndian.Uint32(buf[20:24])
			fmt.Printf("auth_key_id: 0x%016x\n", resp_auth_key_id)
			fmt.Printf("msg_id: 0x%016x\n", resp_msg_id)
			fmt.Printf("msg_len: %d\n", resp_msg_len)
			fmt.Printf("constructor: 0x%08x\n", constructor)
			if constructor == 0x05162463 {
				fmt.Println("✅ resPQ! MTProto握手成功!")
			}
		}
	}
}
