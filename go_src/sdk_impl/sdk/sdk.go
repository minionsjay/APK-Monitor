package sdk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type SecretPayload struct {
	AppDomain     string `json:"app_domain"`
	AppDomainPort int    `json:"app_domain_port,omitempty"`
	AppName       string `json:"app_name"`
	SDKVersion    string `json:"sdk_version,omitempty"`
	AESKey        string `json:"AES-key"`
	SNI           string `json:"sni,omitempty"`
	DatURL        string `json:"dat_url,omitempty"`
	Port          int    `json:"port,omitempty"`
}

type NodeGroups struct {
	NodesA []string `json:"nodesA"`
	NodesB []string `json:"nodesB,omitempty"`
	NodesC []string `json:"nodesC,omitempty"`
	NodesD []string `json:"nodesD,omitempty"`
	NodesE []string `json:"nodesE,omitempty"`
}

type FwdHelloRequest struct {
	Version       string `json:"version"`
	Type          string `json:"type"`
	Nonce         string `json:"nonce"`
	MAC           string `json:"mac"`
	DeviceUUID    string `json:"device_uuid,omitempty"`
	SDKVersion    string `json:"sdk_version,omitempty"`
	TimestampUnix string `json:"timestamp_unix"`
}

type SDK struct {
	AESKey     string
	AppDomain  string
	AppPort    int
	AppName    string
	SDKVersion string
	DeviceUUID string
}

func NewSDK(payload *SecretPayload, deviceUUID string) *SDK {
	return &SDK{
		AESKey:     payload.AESKey,
		AppDomain:  payload.AppDomain,
		AppPort:    payload.AppDomainPort,
		AppName:    payload.AppName,
		SDKVersion: payload.SDKVersion,
		DeviceUUID: deviceUUID,
	}
}

func DecryptSecretPayload(payloadB64, privateKeyPEM string) (*SecretPayload, error) {
	encData, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("PEM decode failed")
	}
	var privKey *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		privKey = k
	} else if k2, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		privKey, _ = k2.(*rsa.PrivateKey)
	}
	if privKey == nil {
		return nil, fmt.Errorf("RSA key parse failed")
	}
	decData, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, encData)
	if err != nil {
		return nil, fmt.Errorf("RSA decrypt: %w", err)
	}
	var payload SecretPayload
	if err := json.Unmarshal(decData, &payload); err != nil {
		return nil, fmt.Errorf("JSON: %w", err)
	}
	return &payload, nil
}

func (s *SDK) ResolveControlPlane() (string, error) {
	domain := fmt.Sprintf("_dns.%s", s.AppDomain)
	txts, err := lookupTXT(domain)
	if err != nil {
		return "", err
	}
	if len(txts) == 0 {
		return "", fmt.Errorf("no TXT records")
	}
	return decryptTXT(txts[0], s.AESKey)
}

func lookupTXT(domain string) ([]string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://dns.alidns.com/resolve?name=%s&type=TXT", domain)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Answer []struct {
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	var txts []string
	for _, a := range result.Answer {
		txts = append(txts, strings.Trim(a.Data, "\""))
	}
	return txts, nil
}

func decryptTXT(txt, aesKey string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(txt)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return "", err
	}
	iv := []byte(aesKey)[:16]
	dec := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dec, data)
	pad := int(dec[len(dec)-1])
	if pad > 0 && pad <= 16 {
		dec = dec[:len(dec)-pad]
	}
	return string(dec), nil
}

func (s *SDK) FetchNodeGroups(datURL string) (*NodeGroups, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(datURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return s.DecryptNodeData(data)
}

func (s *SDK) DecryptNodeData(data []byte) (*NodeGroups, error) {
	var groups NodeGroups
	if err := json.Unmarshal(data, &groups); err == nil {
		return &groups, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		if err := json.Unmarshal(decoded, &groups); err == nil {
			return &groups, nil
		}
		data = decoded
	}
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("data len %d not multiple of 16", len(data))
	}
	block, err := aes.NewCipher([]byte(s.AESKey))
	if err != nil {
		return nil, err
	}
	iv := []byte(s.AESKey)[:16]
	dec := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(dec, data)
	pad := int(dec[len(dec)-1])
	if pad > 0 && pad <= 16 {
		dec = dec[:len(dec)-pad]
	}
	if err := json.Unmarshal(dec, &groups); err != nil {
		return nil, fmt.Errorf("JSON: %w", err)
	}
	return &groups, nil
}

func ShortMD5(data []byte) string {
	h := md5.Sum(data)
	return hex.EncodeToString(h[:])[:16]
}

func RandomNonce() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf) + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func RandomLabel() string {
	buf := make([]byte, 8)
	rand.Read(buf)
	return hex.EncodeToString(buf) + strconv.FormatInt(time.Now().UnixNano(), 10)
}

func HMACSHA256Hex(key, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *SDK) SignForwarderHelloMAC(nonce, label string) string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	fields := []string{"2", "hello", nonce, s.DeviceUUID, ts, "2", label, ""}
	return HMACSHA256Hex(s.AESKey, strings.Join(fields, "."))
}

func BuildDeadBEEFFrame(payload []byte) []byte {
	n, _ := rand.Int(rand.Reader, big.NewInt(64))
	paddingLen := int(n.Int64())
	padding := make([]byte, paddingLen)
	rand.Read(padding)
	buf := make([]byte, 0, 4+2+2+1+paddingLen+len(payload))
	buf = append(buf, 0xDE, 0xAD, 0xBE, 0xEF)
	buf = append(buf, 0x00, 0x00)
	buf = append(buf, byte(len(payload)>>8), byte(len(payload)))
	buf = append(buf, byte(paddingLen))
	buf = append(buf, padding...)
	buf = append(buf, payload...)
	return buf
}

func (s *SDK) TLSConfig(sni string) *tls.Config {
	return &tls.Config{
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
	}
}

func AuthKeyID(masterSecret []byte) string {
	h := sha1.Sum(masterSecret)
	return hex.EncodeToString(h[:8])
}
