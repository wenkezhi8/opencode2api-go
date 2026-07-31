package main

import (
	"os"
	"sync"
	"testing"
)

// 恢复全局状态的 helper
func resetState() {
	configMu.Lock()
	modelAlias = map[string]string{}
	apiKey = ""
	configMu.Unlock()
	modelBlocklistMu.Lock()
	modelBlocklist = map[string]bool{}
	modelBlocklistMu.Unlock()
	tokenStatsMu.Lock()
	tokenStats = &TokenStatsData{Models: map[string]*ModelStats{}}
	tokenStatsMu.Unlock()
	// 排空异步保存信号，避免后台 loop 用空数据覆盖测试文件
	drainSaveCh()
}

// 排空异步保存 channel
func drainSaveCh() {
	for {
		select {
		case <-tokenStatsSaveCh:
		default:
			return
		}
	}
}

func TestMain(m *testing.M) {
	resetState()
	// 测试用临时 stats 文件，不污染服务器数据
	tokenStatsPath = "/tmp/oc2api_test_stats.json"
	os.Remove(tokenStatsPath)
	os.Exit(m.Run())
}

// 1. isModelBlocked：被封禁模型返回 true，未被封禁返回 false
func TestIsModelBlocked(t *testing.T) {
	resetState()
	modelBlocklistMu.Lock()
	modelBlocklist["gpt-5"] = true
	modelBlocklist["claude-opus-5"] = true
	modelBlocklistMu.Unlock()

	if !isModelBlocked("gpt-5") {
		t.Error("gpt-5 应该被封禁")
	}
	if !isModelBlocked("claude-opus-5") {
		t.Error("claude-opus-5 应该被封禁")
	}
	if isModelBlocked("deepseek-v4-flash-free") {
		t.Error("deepseek-v4-flash-free 不应被封禁")
	}
	if isModelBlocked("") {
		t.Error("空字符串不应被封禁")
	}
}

// 2. resolveModel：被封禁模型返回空串
func TestResolveModelBlockedReturnsEmpty(t *testing.T) {
	resetState()
	modelBlocklistMu.Lock()
	modelBlocklist["gpt-5"] = true
	modelBlocklistMu.Unlock()

	if got := resolveModel("gpt-5"); got != "" {
		t.Errorf("被封禁模型 resolveModel 应返回空串，实际返回 %q", got)
	}
}

// 3. resolveModel：别名正常解析
func TestResolveModelAlias(t *testing.T) {
	resetState()
	configMu.Lock()
	modelAlias["deepseek-v4-flash"] = "deepseek-v4-flash-free"
	configMu.Unlock()

	if got := resolveModel("deepseek-v4-flash"); got != "deepseek-v4-flash-free" {
		t.Errorf("别名解析错误，期望 deepseek-v4-flash-free，实际 %q", got)
	}
}

// 4. resolveModel：别名指向被封禁模型时返回空串
func TestResolveModelAliasBlocked(t *testing.T) {
	resetState()
	configMu.Lock()
	modelAlias["my-alias"] = "gpt-5"
	configMu.Unlock()
	modelBlocklistMu.Lock()
	modelBlocklist["gpt-5"] = true
	modelBlocklistMu.Unlock()

	if got := resolveModel("my-alias"); got != "" {
		t.Errorf("别名指向被封禁模型应返回空串，实际 %q", got)
	}
}

// 5. resolveModel：未知模型原样返回
func TestResolveModelUnknownPassThrough(t *testing.T) {
	resetState()
	if got := resolveModel("some-random-model"); got != "some-random-model" {
		t.Errorf("未知模型应原样返回，实际 %q", got)
	}
}

// 6. resolveModel：去除前后空格
func TestResolveModelTrimSpace(t *testing.T) {
	resetState()
	if got := resolveModel("  deepseek-v4-flash-free  "); got != "deepseek-v4-flash-free" {
		t.Errorf("应去除空格，实际 %q", got)
	}
}

// 7. recordTokenUsage：累加正确
func TestRecordTokenUsageAccumulate(t *testing.T) {
	resetState()
	recordTokenUsage("m1", 10, 20, 30)
	recordTokenUsage("m1", 5, 15, 20)
	recordTokenUsage("m2", 100, 0, 100)

	tokenStatsMu.Lock()
	defer tokenStatsMu.Unlock()

	if tokenStats.TotalRequests != 3 {
		t.Errorf("TotalRequests 应为 3，实际 %d", tokenStats.TotalRequests)
	}
	m1 := tokenStats.Models["m1"]
	if m1 == nil {
		t.Fatal("m1 不应为 nil")
	}
	if m1.RequestCount != 2 || m1.PromptTokens != 15 || m1.CompletionTokens != 35 || m1.TotalTokens != 50 {
		t.Errorf("m1 统计错误: %+v", m1)
	}
	m2 := tokenStats.Models["m2"]
	if m2 == nil || m2.TotalTokens != 100 {
		t.Errorf("m2 统计错误: %+v", m2)
	}
}

// 8. recordTokenUsage：并发安全（不 panic、不数据竞争）
func TestRecordTokenUsageConcurrent(t *testing.T) {
	resetState()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			recordTokenUsage("concurrent-model", 1, 1, 2)
		}(i)
	}
	wg.Wait()

	tokenStatsMu.Lock()
	defer tokenStatsMu.Unlock()
	if tokenStats.TotalRequests != 100 {
		t.Errorf("并发后 TotalRequests 应为 100，实际 %d", tokenStats.TotalRequests)
	}
	m := tokenStats.Models["concurrent-model"]
	if m == nil || m.RequestCount != 100 || m.TotalTokens != 200 {
		t.Errorf("并发统计错误: %+v", m)
	}
}

// 9. maskKey：脱敏正确
func TestMaskKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "****"},
		{"ab", "****"},
		{"abcd", "****"},
		{"abcde", "ab****de"},
		{"sk-1234567890", "sk****90"},
		{"wenkezhi", "we****hi"},
	}
	for _, c := range cases {
		if got := maskKey(c.in); got != c.want {
			t.Errorf("maskKey(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// 10. applyConfig：清空 API Key 生效（原 bug 是 if apiKey != "" 导致无法清空）
func TestApplyConfigClearAPIKey(t *testing.T) {
	resetState()
	// 先设置一个 key
	applyConfig(AppConfig{APIKey: "wenkezhi"})
	if apiKey != "wenkezhi" {
		t.Fatalf("设置 key 失败: %q", apiKey)
	}
	// 再用空字符串清空
	applyConfig(AppConfig{APIKey: ""})
	if apiKey != "" {
		t.Errorf("清空 API Key 失败，当前 %q（应为空）", apiKey)
	}
}

// 11. applyConfig：ModelBlocklist 为 nil 时启用默认列表
func TestApplyConfigDefaultBlocklist(t *testing.T) {
	resetState()
	applyConfig(AppConfig{}) // blocklist 为 nil
	if !isModelBlocked("gpt-5") {
		t.Error("默认 blocklist 应包含 gpt-5")
	}
	if !isModelBlocked("big-pickle") {
		t.Error("默认 blocklist 应包含 big-pickle")
	}
	if isModelBlocked("deepseek-v4-flash-free") {
		t.Error("默认 blocklist 不应包含 deepseek-v4-flash-free")
	}
}

// 12. applyConfig：自定义 blocklist 覆盖默认
func TestApplyConfigCustomBlocklist(t *testing.T) {
	resetState()
	applyConfig(AppConfig{ModelBlocklist: []string{"my-only-blocked"}})
	if !isModelBlocked("my-only-blocked") {
		t.Error("自定义 blocklist 应包含 my-only-blocked")
	}
	if isModelBlocked("gpt-5") {
		t.Error("自定义 blocklist 应覆盖默认，gpt-5 不应被封禁")
	}
}

// 13. saveTokenStats + loadTokenStats：写入读取往返
// 不用 recordTokenUsage（会触发异步 loop），直接操作内存数据后同步保存，
// 这样测试只验证 save/load 本身的正确性
func TestSaveLoadTokenStats(t *testing.T) {
	resetState()
	// 直接填充内存数据
	tokenStatsMu.Lock()
	tokenStats.TotalRequests = 1
	tokenStats.Models["rt-model"] = &ModelStats{RequestCount: 1, PromptTokens: 10, CompletionTokens: 20, TotalTokens: 30}
	tokenStatsMu.Unlock()
	drainSaveCh()
	saveTokenStats()

	// 校验文件可被正常解析（无撕裂）
	loadTokenStats()
	tokenStatsMu.Lock()
	m := tokenStats.Models["rt-model"]
	if m == nil || m.TotalTokens != 30 || m.RequestCount != 1 {
		tokenStatsMu.Unlock()
		t.Errorf("loadTokenStats 往返错误: %+v", m)
		return
	}
	tokenStatsMu.Unlock()

	// load 后再次 save 应幂等
	saveTokenStats()
	loadTokenStats()
	tokenStatsMu.Lock()
	defer tokenStatsMu.Unlock()
	m2 := tokenStats.Models["rt-model"]
	if m2 == nil || m2.TotalTokens != 30 {
		t.Errorf("二次 save/load 不幂等: %+v", m2)
	}
}

// 14. resolveModel：别名源名即使在 blocklist 中也能正常解析（回归测试）
// 复现 bug：deepseek-v4-flash 在默认 blocklist，但有别名 -> deepseek-v4-flash-free
func TestResolveModelAliasSourceInBlocklist(t *testing.T) {
	resetState()
	// 模拟真实配置
	configMu.Lock()
	modelAlias["deepseek-v4-flash"] = "deepseek-v4-flash-free"
	modelAlias["gpt-5.2"] = "deepseek-v4-flash-free"
	configMu.Unlock()
	modelBlocklistMu.Lock()
	modelBlocklist["deepseek-v4-flash"] = true   // 别名源名也在黑名单（真实默认配置）
	modelBlocklist["gpt-5.2"] = true              // 别名源名也在黑名单
	modelBlocklist["real-blocked"] = true         // 真正被封禁的无别名模型
	modelBlocklistMu.Unlock()

	// 别名源名应解析为别名目标，不受 blocklist 影响
	if got := resolveModel("deepseek-v4-flash"); got != "deepseek-v4-flash-free" {
		t.Errorf("别名源名应解析为 deepseek-v4-flash-free，实际 %q", got)
	}
	if got := resolveModel("gpt-5.2"); got != "deepseek-v4-flash-free" {
		t.Errorf("别名源名 gpt-5.2 应解析为 deepseek-v4-flash-free，实际 %q", got)
	}
	// 无别名的被封禁模型仍应返回空
	if got := resolveModel("real-blocked"); got != "" {
		t.Errorf("无别名的被封禁模型应返回空，实际 %q", got)
	}
}

// 15. resolveModel：别名目标被封禁时返回空
func TestResolveModelAliasTargetBlocked(t *testing.T) {
	resetState()
	configMu.Lock()
	modelAlias["my-alias"] = "blocked-target"
	configMu.Unlock()
	modelBlocklistMu.Lock()
	modelBlocklist["blocked-target"] = true
	modelBlocklistMu.Unlock()

	if got := resolveModel("my-alias"); got != "" {
		t.Errorf("别名目标被封禁应返回空，实际 %q", got)
	}
}
