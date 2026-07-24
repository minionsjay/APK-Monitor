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

	// MTProto req_pq_multi
	nonce := make([]byte, 16)
	for i := range nonce { nonce[i] = byte(i + 1) }
	
	mtproto := make([]byte, 40)
	binary.LittleEndian.PutUint64(mtproto[0:8], 0) // auth_key_id=0
	msg_id := uint64(time.Now().Unix()) << 32
	binary.LittleEndian.PutUint64(mtproto[8:16], msg_id)
	binary.LittleEndian.PutUint32(mtproto[16:20], 20)
	binary.LittleEndian.PutUint32(mtproto[20:24], 0xbe7e8720)
	copy(mtproto[24:40], nonce)

	// 尝试不同格式
	tests := []struct{
		name string
		msg  []byte
	}{
		{
			"sublen=0+payload_len=40",
			func() []byte {
				msg := make([]byte, 9+40)
				binary.BigEndian.PutUint32(msg[0:4], 0xDEADBEEF)
				binary.BigEndian.PutUint16(msg[4:6], 0)
				binary.BigEndian.PutUint16(msg[6:8], 40)
				msg[8] = 0
				copy(msg[9:], mtproto)
				return msg
			}(),
		},
		{
			"sublen=40+no_payload_len",
			func() []byte {
				msg := make([]byte, 7+40)
				binary.BigEndian.PutUint32(msg[0:4], 0xDEADBEEF)
				binary.BigEndian.PutUint16(msg[4:6], 40)
				msg[6] = 0
				copy(msg[7:], mtproto)
				return msg
			}(),
		},
		{
			"sublen=0+payload_len=0+pad=0",
			func() []byte {
				msg := make([]byte, 9)
				binary.BigEndian.PutUint32(msg[0:4], 0xDEADBEEF)
				binary.BigEndian.PutUint16(msg[4:6], 0)
				binary.BigEndian.PutUint16(msg[6:8], 0)
				msg[8] = 0
				return msg
			}(),
		},
		{
			"raw_req_pq_multi_no_deadbeef",
			mtproto,
		},
	}

	for _, t := range tests {
		fmt.Printf("\n=== %s (%d bytes) ===\n", t.name, len(t.msg))
		fmt.Printf("发送: %s\n", hex.EncodeToString(t.msg[:min(len(t.msg), 40)]))
		
		conn2, _ := tls.Dial("tcp", server, &tls.Config{
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
		if conn2 == nil { continue }
		
		conn2.SetDeadline(time.Now().Add(5 * time.Second))
		conn2.Write(t.msg)
		
		buf := make([]byte, 4096)
		n, err := conn2.Read(buf)
		if err != nil {
			fmt.Printf("结果: %v\n", err)
		} else {
			fmt.Printf("✅ 收到 %d 字节: %s\n", n, hex.EncodeToString(buf[:min(n, 40)]))
		}
		conn2.Close()
	}
}

func min(a, b int) int { if a < b { return a }; return b }
