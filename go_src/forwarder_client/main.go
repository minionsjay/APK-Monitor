package main

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

func main() {
	// 读取tgnet.dat获取永久auth_key
	tgnet, _ := os.ReadFile("/data/local/tmp/tgnet.dat")
	authKey := make([]byte, 256)
	copy(authKey, tgnet[0x88:0x188])
	
	// auth_key_id from 0x188
	authKeyID := tgnet[0x188:0x190]
	
	fmt.Printf("永久auth_key: %s...\n", hex.EncodeToString(authKey[:8]))
	fmt.Printf("auth_key_id: %s\n", hex.EncodeToString(authKeyID))

	// 构建一个简单的MTProto消息
	// 从截获的224B消息格式：
	// inner = auth_key_id(8) + msg_key(16) + pad1(1) + encrypted_data(16k)
	
	// 构建plaintext
	// 可能是一个简单的请求消息
	// 从标准MTProto：消息格式是 TL对象
	// 试发送一个简单的TL对象
	// 如 req_pq_multi 或自定义消息
	
	// 先构建一个最小的plaintext (16字节)
	plaintext := make([]byte, 16)
	// 填充一些数据
	plaintext[0] = 0x08 // 可能是消息类型
	binary.BigEndian.PutUint64(plaintext[8:], uint64(time.Now().UnixNano()/1000000))
	
	// MTProto v2加密
	// msg_key_src = auth_key[88:96] + plaintext
	msgKeySrc := append(authKey[88:96], plaintext...)
	msgKeySum := sha256.Sum256(msgKeySrc)
	msgKey := msgKeySum[:16]
	
	// aes_key = SHA256(msg_key + auth_key[0:32] + auth_key[64:96])
	keySrc := append(append([]byte{}, msgKey...), authKey[0:32]...)
	keySrc = append(keySrc, authKey[64:96]...)
	aesKey := sha256.Sum256(keySrc)
	
	// aes_iv = SHA256(auth_key[32:64] + msg_key + auth_key[96:128])
	ivSrc := append(append([]byte{}, authKey[32:64]...), msgKey...)
	ivSrc = append(ivSrc, authKey[96:128]...)
	aesIV := sha256.Sum256(ivSrc)
	
	// AES-IGE加密
	encData, err := aesIGEEncrypt(aesKey[:], aesIV[:], plaintext)
	if err != nil {
		fmt.Printf("加密错误: %v\n", err)
		return
	}
	
	// 构建inner
	pad1 := byte(0x00) // padding length?
	inner := make([]byte, 0, 8+16+1+len(encData))
	inner = append(inner, authKeyID...)
	inner = append(inner, msgKey...)
	inner = append(inner, pad1)
	inner = append(inner, encData...)
	
	// 构建DEADBEEF帧
	frame := buildDeadBEEFFrame(inner)
	
	fmt.Printf("\nDEADBEEF帧: %d字节\n", len(frame))
	fmt.Printf("inner: %d字节\n", len(inner))
	fmt.Printf("enc_data: %d字节\n", len(encData))
	
	// TLS连接
	nodes := []string{"43.248.2.74:30139", "8.134.180.186:30139", "8.138.152.138:30139"}
	
	for _, node := range nodes {
		fmt.Printf("\n=== %s ===\n", node)
		err := sendFrame(node, "mail.163.com", frame)
		if err != nil {
			fmt.Printf("失败: %v\n", err)
		}
	}
}

func sendFrame(node, sni string, frame []byte) error {
	conn, err := net.DialTimeout("tcp", node, 10*time.Second)
	if err != nil { return err }
	defer conn.Close()
	
	config := &utls.Config{
		InsecureSkipVerify: true, ServerName: sni,
		MinVersion: utls.VersionTLS12, MaxVersion: utls.VersionTLS12,
	}
	uConn := utls.UClient(conn, config, utls.HelloCustom)
	spec := &utls.ClientHelloSpec{
		CipherSuites: []uint16{0xc00a, 0xc014, 0x0039, 0x006b, 0x0035, 0x003d,
			0xc007, 0xc009, 0xc023, 0xc011, 0xc013, 0xc027,
			0x0033, 0x0067, 0x0032, 0x0005, 0x0004, 0x002f, 0x003c, 0x000a},
		CompressionMethods: []byte{0x01, 0x00},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: sni},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{0x001d, 0x0017, 0x0018, 0x0019}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
			&utls.SessionTicketExtension{},
			&utls.GenericExtension{Id: 0x3374},
			&utls.ALPNExtension{AlpnProtocols: []string{"spdy/2", "spdy/3", "spdy/3.1", "http/1.1"}},
			&utls.GenericExtension{Id: 0x754f},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0402, 0x0202}},
		},
	}
	if err := uConn.ApplyPreset(spec); err != nil { return err }
	if err := uConn.Handshake(); err != nil { return err }
	defer uConn.Close()
	
	fmt.Printf("TLS OK\n")
	
	// 发送DEADBEEF帧
	uConn.SetDeadline(time.Now().Add(10 * time.Second))
	_, err = uConn.Write(frame)
	if err != nil { return err }
	fmt.Printf("发送 %d字节\n", len(frame))
	
	// 读取响应
	buf := make([]byte, 16384)
	n, err := uConn.Read(buf)
	if err != nil {
		return fmt.Errorf("读取: %w", err)
	}
	
	if n > 0 {
		if buf[0] == 0xDE {
			fmt.Printf("收到 DEADBEEF %d字节!\n", n)
			fmt.Printf("hex: %s\n", hex.EncodeToString(buf[:min(n, 40)]))
			
			// 解析响应
			if n > 9 {
				padLen := int(buf[8])
				inner := buf[9+padLen:]
				if len(inner) >= 25 {
					srvAkid := inner[:8]
					srvMsgKey := inner[8:24]
					srvPad1 := inner[24]
					srvEnc := inner[25:]
					fmt.Printf("auth_key_id: %s\n", hex.EncodeToString(srvAkid))
					fmt.Printf("msg_key: %s\n", hex.EncodeToString(srvMsgKey))
					fmt.Printf("pad1: 0x%02x\n", srvPad1)
					fmt.Printf("enc_data: %d字节\n", len(srvEnc))
				}
			}
		} else {
			fmt.Printf("收到 %d字节: %s\n", n, hex.EncodeToString(buf[:min(n, 40)]))
			// 看是否是HTTP响应
			if buf[0] == 'H' || buf[0] == '<' {
				fmt.Printf("HTTP: %s\n", string(buf[:min(n, 100)]))
			}
		}
	}
	
	return nil
}

func buildDeadBEEFFrame(payload []byte) []byte {
	paddingLen := 0
	buf := make([]byte, 0, 4+2+2+1+paddingLen+len(payload))
	buf = append(buf, 0xDE, 0xAD, 0xBE, 0xEF)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, byte(len(payload)>>8), byte(len(payload)))
	buf = append(buf, byte(paddingLen))
	buf = append(buf, payload...)
	return buf
}

func aesIGEEncrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }
	bs := block.BlockSize()
	
	// 补齐到16字节
	if len(data)%bs != 0 {
		padding := bs - len(data)%bs
		data = append(data, make([]byte, padding)...)
	}
	
	if len(iv) < 2*bs {
		return nil, fmt.Errorf("iv too short")
	}
	
	prevCipher := make([]byte, bs)
	copy(prevCipher, iv[:bs])
	prevPlain := make([]byte, bs)
	copy(prevPlain, iv[bs:2*bs])
	
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		chunk := data[i : i+bs]
		// 加密: C_i = E(P_i XOR prevCipher) XOR prevPlain
		var xored [16]byte
		for j := 0; j < bs; j++ {
			xored[j] = chunk[j] ^ prevCipher[j]
		}
		var enc [16]byte
		block.Encrypt(enc[:], xored[:])
		for j := 0; j < bs; j++ {
			out[i+j] = enc[j] ^ prevPlain[j]
		}
		copy(prevCipher, out[i:i+bs])
		copy(prevPlain, chunk)
	}
	return out, nil
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
