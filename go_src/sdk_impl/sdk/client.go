package sdk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client 完整客户端
type Client struct {
	AESKey     string
	AppDomain  string
	AppPort    int
	AppName    string
	SDKVersion string
	DeviceUUID string

	// 缓存的节点
	ControlIP   string
	ProxyNodes  []string
	DatURL      string
}

// NewClient 创建客户端
func NewClient(aesKey, appDomain string, appPort int) *Client {
	return &Client{
		AESKey:     aesKey,
		AppDomain:  appDomain,
		AppPort:    appPort,
		AppName:    fmt.Sprintf("dh%d", appPort%1000),
		SDKVersion: "4.0.1",
		DeviceUUID: GenerateDeviceUUID(),
	}
}

// FetchNodes 完整获取节点流程
// 1. DNS TXT → 控制面IP
// 2. .dat下载 → 代理节点
func (c *Client) FetchNodes() error {
	// 1. DNS TXT解密
	ip, err := c.ResolveControlPlane()
	if err != nil {
		return fmt.Errorf("控制面IP获取失败: %w", err)
	}
	c.ControlIP = ip

	// 2. 构建dat URL（用已知的OSS地址）
	// 在实际SDK中用shortMD5构建
	// 这里用硬编码的URL
	c.DatURL = fmt.Sprintf("https://%s.oss-accelerate.aliyuncs.com/%s.dat",
		"b2eadc6be5be0722", "5815c1738b945fed")

	// 3. 下载.dat
	groups, err := c.FetchNodeGroups(c.DatURL)
	if err != nil {
		return fmt.Errorf("代理节点获取失败: %w", err)
	}
	c.ProxyNodes = groups.NodesA

	return nil
}

// FetchNodesFromControl 从控制面IP获取节点
// 在控制面IP的所有端口尝试下载.dat
func (c *Client) FetchNodesFromControl() error {
	// 1. DNS TXT解密
	ip, err := c.ResolveControlPlane()
	if err != nil {
		return err
	}
	c.ControlIP = ip

	// 2. 从控制面IP下载.dat
	// 可能的.dat路径
	datPaths := []string{
		"/5815c1738b945fed.dat",
		"/cb26d3953ef7d1dc.dat",
	}

	for _, path := range datPaths {
		url := fmt.Sprintf("https://%s:%d%s", ip, c.AppPort, path)
		groups, err := c.FetchNodeGroups(url)
		if err == nil && len(groups.NodesA) > 0 {
			c.ProxyNodes = groups.NodesA
			c.DatURL = url
			return nil
		}

		// 也试OSS域名
		url2 := fmt.Sprintf("https://%s.oss-accelerate.aliyuncs.com%s",
			"b2eadc6be5be0722", path)
		groups, err = c.FetchNodeGroups(url2)
		if err == nil && len(groups.NodesA) > 0 {
			c.ProxyNodes = groups.NodesA
			c.DatURL = url2
			return nil
		}
	}

	// 3. 用缓存URL
	url3 := "https://b2eadc6be5be0722.oss-accelerate.aliyuncs.com/5815c1738b945fed.dat"
	groups, err := c.FetchNodeGroups(url3)
	if err == nil && len(groups.NodesA) > 0 {
		c.ProxyNodes = groups.NodesA
		c.DatURL = url3
		return nil
	}

	return fmt.Errorf("无法获取节点")
}

// ResolveControlPlane 从DNS TXT获取控制面IP
func (c *Client) ResolveControlPlane() (string, error) {
	domain := fmt.Sprintf("_dns.%s", c.AppDomain)
	txts, err := lookupTXT(domain)
	if err != nil {
		return "", err
	}
	if len(txts) == 0 {
		return "", fmt.Errorf("no TXT")
	}
	return decryptTXT(txts[0], c.AESKey)
}

// FetchNodeGroups 下载并解密.dat
func (c *Client) FetchNodeGroups(url string) (*NodeGroups, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return c.DecryptNodeData(data)
}

// DecryptNodeData AES-CBC解密节点数据
func (c *Client) DecryptNodeData(data []byte) (*NodeGroups, error) {
	// 尝试直接JSON
	var groups NodeGroups
	if err := json.Unmarshal(data, &groups); err == nil {
		return &groups, nil
	}
	// base64解码
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		if err := json.Unmarshal(decoded, &groups); err == nil {
			return &groups, nil
		}
		data = decoded
	}
	// AES-CBC解密
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("len %d not /16", len(data))
	}
	block, _ := aes.NewCipher([]byte(c.AESKey))
	iv := []byte(c.AESKey)[:16]
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

// Status 获取状态
func (c *Client) Status() map[string]interface{} {
	return map[string]interface{}{
		"control_ip":   c.ControlIP,
		"proxy_nodes":   c.ProxyNodes,
		"dat_url":       c.DatURL,
		"device_uuid":   c.DeviceUUID,
		"app_name":      c.AppName,
		"app_port":      c.AppPort,
		"node_count":    len(c.ProxyNodes),
		"timestamp":     time.Now().Unix(),
	}
}

// AuthKeyID 从master_secret计算auth_key_id
func (c *Client) AuthKeyID(masterSecret []byte) string {
	h := sha1.Sum(masterSecret)
	return fmt.Sprintf("%x", h[:8])
}

// GenerateDeviceUUID 生成设备UUID
func GenerateDeviceUUID() string {
	return fmt.Sprintf("%x%d", make([]byte, 16), time.Now().UnixNano())
}

// 确保import使用
var _ = strings.Fields

// SignForwarderHelloMAC 签名forwarder hello MAC
func (c *Client) SignForwarderHelloMAC(nonce, label string) string {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	fields := []string{"2", "hello", nonce, c.DeviceUUID, ts, "2", label, ""}
	return HMACSHA256Hex(c.AESKey, strings.Join(fields, "."))
}
