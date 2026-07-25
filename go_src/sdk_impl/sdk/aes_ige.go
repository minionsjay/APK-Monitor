package sdk

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

func AESIGEEncrypt(key, iv, data []byte) ([]byte, error) {
	return aesIGE(key, iv, data, true)
}

func AESIGEDecrypt(key, iv, data []byte) ([]byte, error) {
	return aesIGE(key, iv, data, false)
}

func aesIGE(key, iv, data []byte, encrypt bool) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes")
	}
	if len(iv) != 32 {
		return nil, errors.New("iv must be 32 bytes")
	}
	if len(data)%16 != 0 {
		return nil, errors.New("data must be multiple of 16")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	prevC := make([]byte, 16)
	prevP := make([]byte, 16)
	copy(prevC, iv[:16])
	copy(prevP, iv[16:32])

	result := make([]byte, len(data))

	for i := 0; i < len(data); i += 16 {
		chunk := data[i : i+16]

		var xored, enc [16]byte
		if encrypt {
			for j := 0; j < 16; j++ {
				xored[j] = chunk[j] ^ prevC[j]
			}
			block.Encrypt(enc[:], xored[:])
			for j := 0; j < 16; j++ {
				result[i+j] = enc[j] ^ prevP[j]
			}
			copy(prevP, chunk)
			copy(prevC, result[i:i+16])
		} else {
			for j := 0; j < 16; j++ {
				xored[j] = chunk[j] ^ prevP[j]
			}
			block.Decrypt(enc[:], xored[:])
			for j := 0; j < 16; j++ {
				result[i+j] = enc[j] ^ prevC[j]
			}
			copy(prevC, chunk)
			copy(prevP, result[i:i+16])
		}
	}

	return result, nil
}

// MTProtoEncrypt MTProto v2加密
func MTProtoEncrypt(authKey, data []byte) ([]byte, error) {
	if len(authKey) < 256 {
		padded := make([]byte, 256)
		copy(padded, authKey)
		authKey = padded
	}

	// msg_key = SHA256(auth_key[88:96] + data)
	msgKeySrc := append(append([]byte{}, authKey[88:96]...), data...)
	h := sha256.Sum256(msgKeySrc)
	msgKey := make([]byte, 16)
	copy(msgKey, h[:16])

	// aes_key = SHA256(msg_key + auth_key[0:32] + auth_key[64:96])
	keySrc := append(append(msgKey, authKey[0:32]...), authKey[64:96]...)
	aesKey := sha256.Sum256(keySrc)

	// aes_iv = SHA256(auth_key[32:64] + msg_key + auth_key[96:128])
	ivSrc := append(append(authKey[32:64], msgKey...), authKey[96:128]...)
	aesIV := sha256.Sum256(ivSrc)

	encrypted, err := AESIGEEncrypt(aesKey[:], aesIV[:], data)
	if err != nil {
		return nil, err
	}

	authKeyHash := sha1.Sum(authKey)
	result := make([]byte, 0, 8+16+len(encrypted))
	result = append(result, authKeyHash[:8]...)
	result = append(result, msgKey...)
	result = append(result, encrypted...)

	return result, nil
}

// MTProtoDecrypt MTProto v2解密
func MTProtoDecrypt(authKey, encrypted []byte) ([]byte, error) {
	if len(authKey) < 256 {
		padded := make([]byte, 256)
		copy(padded, authKey)
		authKey = padded
	}
	if len(encrypted) < 24 {
		return nil, errors.New("encrypted data too short")
	}

	msgKey := make([]byte, 16)
	copy(msgKey, encrypted[8:24])
	encData := encrypted[24:]

	// aes_key = SHA256(msg_key + auth_key[0:32] + auth_key[64:96])
	keySrc := append(append([]byte{}, msgKey...), authKey[0:32]...)
	keySrc = append(keySrc, authKey[64:96]...)
	aesKey := sha256.Sum256(keySrc)

	// aes_iv = SHA256(auth_key[32:64] + msg_key + auth_key[96:128])
	ivSrc := append(append([]byte{}, authKey[32:64]...), msgKey...)
	ivSrc = append(ivSrc, authKey[96:128]...)
	aesIV := sha256.Sum256(ivSrc)

	return AESIGEDecrypt(aesKey[:], aesIV[:], encData)
}

// MTProtoEncryptV1 MTProto v1加密
func MTProtoEncryptV1(authKey, data []byte) ([]byte, error) {
	if len(authKey) < 256 {
		padded := make([]byte, 256)
		copy(padded, authKey)
		authKey = padded
	}

	msgKeySrc := append(data, authKey[0:32]...)
	h := sha1.Sum(msgKeySrc)
	msgKey := make([]byte, 16)
	copy(msgKey, h[:16])

	// key = SHA1(msg_key + auth_key[0:16])[:16] + SHA1(auth_key[0:16] + msg_key)[:16]
	// 等等，MTProto v1的key计算:
	// aes_key = SHA1(msg_key + auth_key[0:16]) + SHA1(auth_key[0:16] + msg_key)
	// 只取前16字节
	kp1 := sha1.Sum(append(msgKey, authKey[0:16]...))
	kp2 := sha1.Sum(append(authKey[0:16], msgKey...))
	aesKey := make([]byte, 32)
	copy(aesKey[:16], kp1[:16])
	copy(aesKey[16:], kp2[:16])

	// iv = SHA1(auth_key[32:48] + msg_key) + SHA1(msg_key + auth_key[48:64])
	// 只取前16字节
	ip1 := sha1.Sum(append(authKey[32:48], msgKey...))
	ip2 := sha1.Sum(append(msgKey, authKey[48:64]...))
	aesIV := make([]byte, 32)
	copy(aesIV[:16], ip1[:16])
	copy(aesIV[16:], ip2[:16])

	encrypted, err := AESIGEEncrypt(aesKey, aesIV, data)
	if err != nil {
		return nil, err
	}

	authKeyHash := sha1.Sum(authKey)
	result := make([]byte, 0, 8+16+len(encrypted))
	result = append(result, authKeyHash[:8]...)
	result = append(result, msgKey...)
	result = append(result, encrypted...)

	return result, nil
}

func AuthKeyID(masterSecret []byte) string {
	h := sha1.Sum(masterSecret)
	return hex.EncodeToString(h[:8])
}
