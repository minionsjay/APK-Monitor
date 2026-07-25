package sdk

// gomobile绑定入口
// 编译: gomobile bind -target=android/arm64 -o proxy.aar

/*
#include <jni.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"log"
	"sync"
)

// ProxyManager 管理代理生命周期
type ProxyManager struct {
	mu        sync.Mutex
	proxy     *UTLSProxyServer
	config    *ProxyConfig
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	AESKey     string
	ProxyAddr  string
	SNI        string
	DeviceUUID string
	LocalPort  int
}

var defaultManager *ProxyManager
var initOnce sync.Once

// GetProxyManager 获取单例
func GetProxyManager() *ProxyManager {
	initOnce.Do(func() {
		defaultManager = &ProxyManager{}
	})
	return defaultManager
}

// SetConfig 设置配置
func (pm *ProxyManager) SetConfig(aesKey, proxyAddr, sni, deviceUUID string, localPort int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.config = &ProxyConfig{
		AESKey:     aesKey,
		ProxyAddr:  proxyAddr,
		SNI:        sni,
		DeviceUUID: deviceUUID,
		LocalPort:  localPort,
	}
}

// Start 启动代理
func (pm *ProxyManager) Start() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.proxy != nil {
		return fmt.Errorf("already running")
	}
	if pm.config == nil {
		return fmt.Errorf("config not set")
	}
	pm.proxy = NewUTLSProxyServer(
		pm.config.AESKey,
		pm.config.ProxyAddr,
		pm.config.SNI,
		pm.config.DeviceUUID,
		pm.config.LocalPort,
	)
	return pm.proxy.Start()
}

// Stop 停止代理
func (pm *ProxyManager) Stop() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.proxy != nil {
		pm.proxy.Stop()
		pm.proxy = nil
	}
}

// IsRunning 是否运行中
func (pm *ProxyManager) IsRunning() bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.proxy != nil
}

// ResolveNodes 获取代理节点
func (pm *ProxyManager) ResolveNodes(appDomain, aesKey string) ([]string, error) {
	s := &SDK{
		AESKey:    aesKey,
		AppDomain: appDomain,
	}
	// 1. DNS TXT → 控制面IP
	ip, err := s.ResolveControlPlane()
	if err != nil {
		return nil, err
	}
	// 2. .dat下载 → 代理节点
	// 需要构建.dat URL
	// 这里用缓存的URL
	datURL := fmt.Sprintf("https://%s/placeholder.dat", ip)
	groups, err := s.FetchNodeGroups(datURL)
	if err != nil {
		return nil, err
	}
	return groups.NodesA, nil
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
