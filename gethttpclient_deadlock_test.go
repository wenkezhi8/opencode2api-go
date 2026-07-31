package main

import (
	"sync"
	"testing"
	"time"
)

// 回归测试：getHTTPClient 在 RR（round_robin）模式下并发调用不能死锁
// 复现旧 bug：函数开头 RLock + defer RUnlock，RR 分支里再 Lock → 读锁升级写锁 → 死锁
func TestGetHTTPClientRRNoDeadlock(t *testing.T) {
	socks5Mu.Lock()
	activeSocks5 = socks5RR
	socks5Proxies = []Socks5Proxy{
		{Addr: "127.0.0.1:1"},
		{Addr: "127.0.0.1:2"},
		{Addr: "127.0.0.1:3"},
	}
	socks5Client = nil
	socks5ClientAddr = ""
	socks5Clients = nil
	socks5Mu.Unlock()

	done := make(chan struct{})
	go func() {
		// 并发 20 goroutine 各调 50 次
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					getHTTPClient()
				}
			}()
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// 通过：没有死锁
	case <-time.After(5 * time.Second):
		t.Fatal("DEADLOCK: getHTTPClient 在 RR 模式下并发调用死锁了")
	}

	// 恢复状态
	socks5Mu.Lock()
	activeSocks5 = ""
	socks5Proxies = nil
	socks5Mu.Unlock()
}

// 固定代理模式同样不能死锁
func TestGetHTTPClientFixedNoDeadlock(t *testing.T) {
	socks5Mu.Lock()
	activeSocks5 = "127.0.0.1:1080"
	socks5Proxies = []Socks5Proxy{{Addr: "127.0.0.1:1080"}}
	socks5Client = nil
	socks5ClientAddr = ""
	socks5Clients = nil
	socks5Mu.Unlock()

	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					getHTTPClient()
				}
			}()
		}
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DEADLOCK: getHTTPClient 固定代理模式并发死锁")
	}

	socks5Mu.Lock()
	activeSocks5 = ""
	socks5Proxies = nil
	socks5Mu.Unlock()
}
