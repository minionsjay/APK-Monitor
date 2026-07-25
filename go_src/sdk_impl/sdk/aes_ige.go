package sdk

import (
	"crypto/aes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

// AESIGEEncrypt AES-IGE加密
func AESIGEEncrypt(key, iv, data []byte) ([]byte, error) {
	return aesIGE(key, iv, data, true)
}

// AESIGEDecrypt AES-IGE解密
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

	// IGE: prevCipher = iv[0:16], prevPlain = iv[16:32]
	prevCipher := make([]byte, 16)
	prevPlain := make([]byte, 16)
	copy(prevCipher, iv[0:16]) // first 16 bytes of IV
	copy(prevPlain, iv[16:32]) // last 16 bytes of IV

	result := make([]byte, len(data))

	for i := 0; i < len(data); i += 16 {
		chunk := make([]byte, 16)
		copy(chunk, data[i:i+16])

		// XOR with prevCipher
		xored := make([]byte, 16)
		if encrypt {
			for j := 0; j < 16; j++ {
				xored[j] = chunk[j] ^ prevCipher[j]
			}
		} else {
			for j := 0; j < 16; j++ {
				xored[j] = chunk[j] ^ prevPlain[j]
			}
		}

		// AES encrypt
		enc := make([]byte, 16)
		if encrypt {
			block.Encrypt(enc, xored)
		} else {
			block.Decrypt(enc, xored)
		}

		// XOR with prevPlain (encrypt) or prevCipher (decrypt)
		out := make([]byte, 16)
		if encrypt {
			for j := 0; j < 16; j++ {
				out[j] = enc[j] ^ prevPlain[j]
			}
		} else {
			for j := 0; j < 16; j++ {
				out[j] = enc[j] ^ prevCipher[j]
			}
		}

		copy(result[i:i+16], out)

		// Update prev values
		if encrypt {
			copy(prevPlain, chunk)
			copy(prevCipher, out)
		} else {
			copy(prevCipher, chunk)
			copy(prevPlain, out)
		}
	}

	return result, nil
}

// MTProtoEncrypt MTProto v2加密
// authKey: 256字节auth_key (master_secret的某种派生)
// data: 明文数据(需要16字节对齐)
// 返回: auth_key_id(8B) + msg_key(16B) + encrypted_data
func MTProtoEncrypt(authKey, data []byte) ([]byte, error) {
	if len(authKey) < 256 {
		// 如果auth_key不足256字节，补零
		padded := make([]byte, 256)
		copy(padded, authKey)
		authKey = padded
	}

	// 1. 计算msg_key (MTProto v2)
	// msg_key = SHA256(authKey[88:96] + data)
	msgKeySrc := make([]byte, 8+len(data))
	copy(msgKeySrc, authKey[88:96])
	copy(msgKeySrc[8:], data)
	h := sha256.Sum256(msgKeySrc)
	msgKey := h[:16]

	// 2. 计算AES key和IV
	// key = SHA256(msgKey + authKey[0:32])
	// iv = SHA256(msgKey + authKey[32:64])
	aesKey := sha256.Sum256(append(msgKey, authKey[0:32]...))
	aesIV := sha256.Sum256(append(msgKey, authKey[32:64]...))

	// 3. AES-IGE加密
	encrypted, err := AESIGEEncrypt(aesKey[:], aesIV[:], data)
	if err != nil {
		return nil, err
	}

	// 4. auth_key_id = SHA1(authKey)[:8]
	authKeyHash := sha1.Sum(authKey)

	// 5. 构建: auth_key_id(8B) + msg_key(16B) + encrypted_data
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

	// 提取auth_key_id和msg_key
	// authKeyID := encrypted[:8]
	msgKey := encrypted[8:24]
	encData := encrypted[24:]

	// 计算AES key和IV
	aesKey := sha256.Sum256(append(msgKey, authKey[0:32]...))
	aesIV := sha256.Sum256(append(msgKey, authKey[32:64]...))

	// AES-IGE解密
	return AESIGEDecrypt(aesKey[:], aesIV[:], encData)
}

// MTProtoEncryptV1 MTProto v1加密 (旧版本)
// msg_key = SHA1(data + authKey[0:32])[0:16]
func MTProtoEncryptV1(authKey, data []byte) ([]byte, error) {
	if len(authKey) < 256 {
		padded := make([]byte, 256)
		copy(padded, authKey)
		authKey = padded
	}

	// msg_key = SHA1(data + authKey[0:32])[0:16]
	msgKeySrc := make([]byte, len(data)+32)
	copy(msgKeySrc, data)
	copy(msgKeySrc[len(data):], authKey[0:32])
	h := sha1.Sum(msgKeySrc)
	msgKey := h[:16]

	// key = SHA1(msgKey + authKey[0:16]) + SHA1(msgKey + authKey[16:32])[0:16]
	keyPart1 := sha1.Sum(append(msgKey, authKey[0:16]...))
	keyPart2 := sha1.Sum(append(msgKey, authKey[16:32]...))
	aesKey := make([]byte, 32)
	copy(aesKey[:16], keyPart1[:16])
	copy(aesKey[16:], keyPart2[:16])

	// iv = SHA1(authKey[32:48] + msgKey) + SHA1(msgKey + authKey[48:64])[0:16]
	ivPart1 := sha1.Sum(append(authKey[32:48], msgKey...))
	ivPart2 := sha1.Sum(append(msgKey, authKey[48:64]...))
	aesIV := make([]byte, 32)
	copy(aesIV[:16], ivPart1[:16])
	copy(aesIV[16:], ivPart2[:16])

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

// helper: for testing
var _ hash.Hash // ensure hash import used
var _ = binary.BigEndian
