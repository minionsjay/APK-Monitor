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
	tgnet, _ := os.ReadFile("/data/local/tmp/tgnet.dat")
	authKey := make([]byte, 256)
	copy(authKey, tgnet[0x88:0x188])
	authKeyID := tgnet[0x188:0x190]
	
	fmt.Printf("auth_key: %s...\n", hex.EncodeToString(authKey[:8]))
	fmt.Printf("auth_key_id: %s\n", hex.EncodeToString(authKeyID))
	
	// 试不同大小的plaintext
	// 从截获消息推断的plaintext大小
	sizes := []struct {
		name string
		plainLen int
		pad1 byte
	}{
		{"224B-msg", 144, 0xd6},  // enc=144
		{"264B-msg", 224, 0xe3},  // enc=224
		{"318B-msg", 240, 0x30},  // enc=240
		{"592B-msg", 521, 0x62},  // enc=521
	}
	
	node := "43.248.2.74:30139"
	sni := "mail.163.com"
	
	for _, s := range sizes {
		fmt.Printf("\n=== %s (plain=%d pad1=0x%02x) ===\n", s.name, s.plainLen, s.pad1)
		
		// 构建plaintext
		plaintext := make([]byte, s.plainLen)
		// 填充一些数据
		for i := range plaintext {
			plaintext[i] = byte(i)
		}
		// 补齐到16字节
		if len(plaintext)%16 != 0 {
			padding := 16 - len(plaintext)%16
			plaintext = append(plaintext, make([]byte, padding)...)
		}
		
		// MTProto v2加密
		msgKeySrc := append(authKey[88:96], plaintext...)
		msgKeySum := sha256.Sum256(msgKeySrc)
		msgKey := msgKeySum[:16]
		
		keySrc := append(append([]byte{}, msgKey...), authKey[0:32]...)
		keySrc = append(keySrc, authKey[64:96]...)
		aesKey := sha256.Sum256(keySrc)
		
		ivSrc := append(append([]byte{}, authKey[32:64]...), msgKey...)
		ivSrc = append(ivSrc, authKey[96:128]...)
		aesIV := sha256.Sum256(ivSrc)
		
		encData, err := aesIGEEncrypt(aesKey[:], aesIV[:], plaintext)
		if err != nil {
			fmt.Printf("加密错误: %v\n", err)
			continue
		}
		
		// 构建inner
		inner := make([]byte, 0, 8+16+1+len(encData))
		inner = append(inner, authKeyID...)
		inner = append(inner, msgKey...)
		inner = append(inner, s.pad1)
		inner = append(inner, encData...)
		
		frame := buildDeadBEEFFrame(inner)
		fmt.Printf("帧: %d字节 inner: %d enc: %d\n", len(frame), len(inner), len(encData))
		
		err = sendFrame(node, sni, frame)
		if err != nil {
			fmt.Printf("结果: %v\n", err)
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
	
	uConn.SetDeadline(time.Now().Add(5 * time.Second))
	uConn.Write(frame)
	
	buf := make([]byte, 16384)
	n, err := uConn.Read(buf)
	if err != nil {
		return fmt.Errorf("读取: %w", err)
	}
	
	if n > 0 {
		if buf[0] == 0xDE {
			fmt.Printf("✅ 收到DEADBEEF %d字节!\n", n)
			fmt.Printf("hex: %s\n", hex.EncodeToString(buf[:min(n, 40)]))
		} else {
			fmt.Printf("收到 %d字节: %s\n", n, hex.EncodeToString(buf[:min(n, 40)]))
		}
	}
	return nil
}

func buildDeadBEEFFrame(payload []byte) []byte {
	buf := make([]byte, 0, 4+2+2+1+len(payload))
	buf = append(buf, 0xDE, 0xAD, 0xBE, 0xEF)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, byte(len(payload)>>8), byte(len(payload)))
	buf = append(buf, 0x00)
	buf = append(buf, payload...)
	return buf
}

func aesIGEEncrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }
	bs := block.BlockSize()
	if len(iv) < 2*bs { return nil, fmt.Errorf("iv short") }
	
	prevC := make([]byte, bs)
	copy(prevC, iv[:bs])
	prevP := make([]byte, bs)
	copy(prevP, iv[bs:2*bs])
	
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		chunk := data[i:i+bs]
		var xored [16]byte
		for j := 0; j < bs; j++ { xored[j] = chunk[j] ^ prevC[j] }
		var enc [16]byte
		block.Encrypt(enc[:], xored[:])
		for j := 0; j < bs; j++ { out[i+j] = enc[j] ^ prevP[j] }
		copy(prevC, out[i:i+bs])
		copy(prevP, chunk)
	}
	return out, nil
}

func min(a, b int) int { if a < b { return a }; return b }
var _ = binary.BigEndian
