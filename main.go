package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var httpClient = &http.Client{
	Timeout: 300 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	},
}

// ======================== SOCKS5 代理 ========================

type Socks5Proxy struct {
	Addr     string `json:"addr"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Name     string `json:"name,omitempty"`
}

func socks5Dial(proxy Socks5Proxy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		conn, err := net.DialTimeout("tcp", proxy.Addr, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("socks5 connect to %s: %w", proxy.Addr, err)
		}
		deadline := time.Now().Add(15 * time.Second)
		conn.SetDeadline(deadline)

		// 认证方法协商
		auth := byte(0x00) // no auth
		if proxy.Username != "" {
			auth = 0x02 // username/password
		}
		if _, err := conn.Write([]byte{0x05, 0x01, auth}); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 handshake write: %w", err)
		}
		buf := make([]byte, 2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 handshake read: %w", err)
		}
		if buf[0] != 0x05 {
			conn.Close()
			return nil, fmt.Errorf("socks5: not socks5 protocol")
		}

		// 用户名/密码认证
		if buf[1] == 0x02 {
			if proxy.Username == "" {
				conn.Close()
				return nil, fmt.Errorf("socks5: server requires auth but no credentials")
			}
			ulen := len(proxy.Username)
			plen := len(proxy.Password)
			authBuf := make([]byte, 3+ulen+plen)
			authBuf[0] = 0x01
			authBuf[1] = byte(ulen)
			copy(authBuf[2:], proxy.Username)
			authBuf[2+ulen] = byte(plen)
			copy(authBuf[3+ulen:], proxy.Password)
			if _, err := conn.Write(authBuf); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5 auth write: %w", err)
			}
			authResp := make([]byte, 2)
			if _, err := io.ReadFull(conn, authResp); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5 auth read: %w", err)
			}
			if authResp[1] != 0x00 {
				conn.Close()
				return nil, fmt.Errorf("socks5: auth failed")
			}
		} else if buf[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5: unsupported auth method 0x%02x", buf[1])
		}

		// CONNECT 请求
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: invalid target %s: %w", target, err)
		}
		port := 0
		fmt.Sscanf(portStr, "%d", &port)

		req := []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV
		ip := net.ParseIP(host)
		if ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				req = append(req, 0x01) // IPv4
				req = append(req, ip4...)
			} else {
				req = append(req, 0x04) // IPv6
				req = append(req, ip.To16()...)
			}
		} else {
			if len(host) > 255 {
				conn.Close()
				return nil, fmt.Errorf("socks5: hostname too long")
			}
			req = append(req, 0x03) // Domain
			req = append(req, byte(len(host)))
			req = append(req, []byte(host)...)
		}
		req = append(req, byte(port>>8), byte(port))

		if _, err := conn.Write(req); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 connect write: %w", err)
		}

		// 读取响应
		resp := make([]byte, 4)
		if _, err := io.ReadFull(conn, resp); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 connect read: %w", err)
		}
		if resp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5: connect failed, status 0x%02x", resp[1])
		}

		// 读取绑定地址
		switch resp[3] {
		case 0x01: // IPv4
			if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5: read bind ipv4: %w", err)
			}
		case 0x03: // Domain
			dlen := make([]byte, 1)
			if _, err := io.ReadFull(conn, dlen); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5: read bind domain len: %w", err)
			}
			if _, err := io.ReadFull(conn, make([]byte, int(dlen[0])+2)); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5: read bind domain: %w", err)
			}
		case 0x04: // IPv6
			if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5: read bind ipv6: %w", err)
			}
		default:
			conn.Close()
			return nil, fmt.Errorf("socks5: unknown address type 0x%02x", resp[3])
		}

		conn.SetDeadline(time.Time{})
		return conn, nil
	}
}

var (
	socks5Proxies []Socks5Proxy
	activeSocks5  string // 启用的代理 Addr，空表示直连，__round_robin__ 表示轮询
	socks5Mu      sync.RWMutex
)

const socks5RR = "__round_robin__"
var socks5RRIndex uint32

var (
	socks5Client      *http.Client // 缓存的 SOCKS5 客户端
	socks5ClientAddr  string       // 缓存对应的代理地址
)

func getHTTPClient() *http.Client {
	socks5Mu.RLock()
	defer socks5Mu.RUnlock()

	if activeSocks5 == "" {
		return httpClient
	}

	var proxy Socks5Proxy
	var useRR bool

	if activeSocks5 == socks5RR {
		if len(socks5Proxies) == 0 {
			return httpClient
		}
		idx := atomic.AddUint32(&socks5RRIndex, 1) % uint32(len(socks5Proxies))
		proxy = socks5Proxies[idx]
		useRR = true
	} else {
		if socks5Client != nil && socks5ClientAddr == activeSocks5 {
			return socks5Client
		}

		var found bool
		for i := range socks5Proxies {
			if socks5Proxies[i].Addr == activeSocks5 {
				proxy = socks5Proxies[i]
				found = true
				break
			}
		}
		if !found {
			return httpClient
		}
	}

	dial := socks5Dial(proxy)
	client := &http.Client{
		Timeout: 300 * time.Second,
		Transport: &http.Transport{
			DialContext:         dial,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	if !useRR {
		socks5Client = client
		socks5ClientAddr = activeSocks5
	}
	return client
}

// ======================== 随机 ID ========================

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = letters[b[i]%byte(len(letters))]
	}
	return string(b)
}

func randomHex(n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = hex[b[i]%byte(len(hex))]
	}
	return string(b)
}

// ======================== OpenCode 会话 ========================

var (
	ocSessionID string
	ocProjectID string
	ocClientVer string
	ocOnce      sync.Once
	requestCount atomic.Int64
)

func fetchOCVersion() string {
	req, _ := http.NewRequest("GET", "https://registry.npmjs.org/opencode-ai/latest", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return "1.15.3"
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var info struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(body, &info) == nil && info.Version != "" {
		return info.Version
	}
	return "1.15.3"
}

func initOCSession() {
	ocOnce.Do(func() {
		ocClientVer = fetchOCVersion()
		ocSessionID = "ses_" + randomString(24)
		ocProjectID = randomHex(40)
		log.Printf("OpenCode Version: %s", ocClientVer)
		log.Printf("Session: %s", ocSessionID)
		log.Printf("Project: %s", ocProjectID)
	})
}

// ======================== 模型 ========================

type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

var (
	modelsCache   []ModelInfo
	modelMu      sync.RWMutex
	modelsLoaded bool
)

func fetchModels() ([]ModelInfo, error) {
	req, _ := http.NewRequest("GET", "https://opencode.ai/zen/v1/models", nil)
	req.Header.Set("Authorization", "Bearer public")
	req.Header.Set("x-opencode-session", ocSessionID)
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	var models []ModelInfo
	now := time.Now().Unix()
	for _, m := range result.Data {
		models = append(models, ModelInfo{ID: m.ID, Object: "model", Created: now, OwnedBy: "opencode"})
	}
	return models, nil
}

func getModelIDs() []string {
	modelMu.RLock()
	defer modelMu.RUnlock()
	ids := make([]string, len(modelsCache))
	for i, m := range modelsCache {
		ids[i] = m.ID
	}
	return ids
}

// ======================== 配置 ========================

var (
	port                 string
	configPath           = "config.json"
	modelAlias           = map[string]string{}
	reasoningEffortMap   = map[string]string{"low": "high", "medium": "high", "xhigh": "max"}
	forceDisableThinking bool
	apiKey               string
	debugMode            bool
	configMu             sync.RWMutex
)

// ======================== Token 统计 ========================

type ModelStats struct {
	RequestCount     int64 `json:"request_count"`
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

type TokenStatsData struct {
	TotalRequests int64                  `json:"total_requests"`
	Models        map[string]*ModelStats `json:"models"`
}

var (
	tokenStats     = &TokenStatsData{Models: map[string]*ModelStats{}}
	tokenStatsMu   sync.Mutex
	tokenStatsPath = "stats.json"
)

// ======================== 数据模型 ========================

type OpenAIRequest struct {
	Model           string                 `json:"model"`
	Messages        []Message              `json:"messages"`
	Stream          bool                   `json:"stream"`
	Temperature     *float64               `json:"temperature,omitempty"`
	MaxTokens       int                    `json:"max_tokens,omitempty"`
	TopP            *float64               `json:"top_p,omitempty"`
	Thinking        any            `json:"thinking,omitempty"`
	ReasoningEffort string                 `json:"reasoning_effort,omitempty"`
	ExtraBody       map[string]any `json:"extra_body,omitempty"`
	Tools           []Tool                 `json:"tools,omitempty"`
	ToolChoice      any            `json:"tool_choice,omitempty"`
}

type Message struct {
	Role             string      `json:"role,omitempty"`
	Content          any `json:"content,omitempty"`
	ToolCalls        []ToolCall  `json:"tool_calls,omitempty"`
	ToolCallID       string      `json:"tool_call_id,omitempty"`
	Name             string      `json:"name,omitempty"`
	ReasoningContent *string     `json:"reasoning_content,omitempty"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type AppConfig struct {
	ModelAlias           map[string]string `json:"model_alias"`
	ReasoningEffortMap   map[string]string `json:"reasoning_effort_map"`
	ForceDisableThinking bool              `json:"force_disable_thinking"`
	Socks5Proxies        []Socks5Proxy     `json:"socks5_proxies,omitempty"`
	ActiveSocks5         string            `json:"active_socks5,omitempty"`
	APIKey               string            `json:"api_key,omitempty"`
}

// ======================== Claude Messages API 类型 ========================

type ClaudeRequest struct {
	Model      string          `json:"model"`
	Messages   []ClaudeMessage `json:"messages"`
	System     any     `json:"system,omitempty"`
	MaxTokens  int             `json:"max_tokens,omitempty"`
	Temperature *float64       `json:"temperature,omitempty"`
	TopP       *float64        `json:"top_p,omitempty"`
	Stream     bool            `json:"stream,omitempty"`
	Tools      []ClaudeTool    `json:"tools,omitempty"`
	ToolChoice any     `json:"tool_choice,omitempty"`
	Metadata   any     `json:"metadata,omitempty"`
	Thinking   any     `json:"thinking,omitempty"`
}

type ClaudeMessage struct {
	Role    string      `json:"role"`
	Content any `json:"content"`
}

type ClaudeContent struct {
	Type      string      `json:"type"`
	Text      string      `json:"text,omitempty"`
	Thinking  string      `json:"thinking,omitempty"`
	Signature string      `json:"signature,omitempty"`
	ID        string      `json:"id,omitempty"`
	Name      string      `json:"name,omitempty"`
	Input     any `json:"input,omitempty"`
	ToolUseID string      `json:"tool_use_id,omitempty"`
	Content   any `json:"content,omitempty"`
}

type ClaudeTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	InputSchema any `json:"input_schema"`
}

type ClaudeResponse struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Role       string          `json:"role"`
	Content    []ClaudeContent `json:"content"`
	Model      string          `json:"model"`
	StopReason string          `json:"stop_reason"`
	Usage      *ClaudeUsage    `json:"usage,omitempty"`
}

type ClaudeUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// ======================== Responses API 类型 ========================

type ResponsesAPIRequest struct {
	Model             string          `json:"model"`
	Input             any     `json:"input"`
	Messages          []Message       `json:"messages,omitempty"`
	Instructions      string          `json:"instructions,omitempty"`
	Stream            bool            `json:"stream,omitempty"`
	Temperature       float64         `json:"temperature,omitempty"`
	MaxTokens         int             `json:"max_output_tokens,omitempty"`
	TopP              float64         `json:"top_p,omitempty"`
	FrequencyPenalty  float64         `json:"frequency_penalty,omitempty"`
	PresencePenalty   float64         `json:"presence_penalty,omitempty"`
	Reasoning         ReasonEffort    `json:"reasoning,omitempty"`
	Include           []string        `json:"include,omitempty"`
	Store             *bool           `json:"store,omitempty"`
	Tools             []ResponsesTool `json:"tools,omitempty"`
	ToolChoice        any     `json:"tool_choice,omitempty"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls,omitempty"`
	Stop              any     `json:"stop,omitempty"`
	User              string          `json:"user,omitempty"`
	StreamOptions     any     `json:"stream_options,omitempty"`
	Metadata          any     `json:"metadata,omitempty"`
}

type ResponsesTool struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	Function    *ToolFunction          `json:"function,omitempty"`
}

type ReasonEffort struct {
	Effort string `json:"effort,omitempty"`
}

// ======================== 配置管理 ========================

func loadConfig(path string) AppConfig {
	var cfg AppConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("警告: 配置文件解析失败: %v", err)
	}
	return cfg
}

func saveConfig(path string, cfg AppConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func applyConfig(cfg AppConfig) {
	configMu.Lock()
	defer configMu.Unlock()
	if cfg.ModelAlias != nil {
		modelAlias = cfg.ModelAlias
	}
	if cfg.ReasoningEffortMap != nil {
		reasoningEffortMap = cfg.ReasoningEffortMap
	}
	forceDisableThinking = cfg.ForceDisableThinking
	if cfg.APIKey != "" {
		apiKey = cfg.APIKey
	}

	socks5Mu.Lock()
	if cfg.Socks5Proxies != nil {
		socks5Proxies = cfg.Socks5Proxies
	}
	if activeSocks5 != cfg.ActiveSocks5 {
		activeSocks5 = cfg.ActiveSocks5
		socks5Client = nil
		socks5ClientAddr = ""
		atomic.StoreUint32(&socks5RRIndex, 0)
	}
	socks5Mu.Unlock()
}

func resolveModel(model string) string {
	m := strings.TrimSpace(model)
	configMu.RLock()
	alias, ok := modelAlias[m]
	configMu.RUnlock()
	if ok {
		return alias
	}
	return m
}

func getForceDisableThinking() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return forceDisableThinking
}

func getReasoningEffortMap() map[string]string {
	configMu.RLock()
	defer configMu.RUnlock()
	cp := make(map[string]string, len(reasoningEffortMap))
	for k, v := range reasoningEffortMap {
		cp[k] = v
	}
	return cp
}

// ======================== Token 统计 ========================

func loadTokenStats() {
	data, err := os.ReadFile(tokenStatsPath)
	if err != nil {
		return
	}
	var st TokenStatsData
	if err := json.Unmarshal(data, &st); err != nil {
		return
	}
	tokenStatsMu.Lock()
	if st.Models == nil {
		st.Models = map[string]*ModelStats{}
	}
	tokenStats = &st
	tokenStatsMu.Unlock()
}

func saveTokenStats() {
	tokenStatsMu.Lock()
	data, err := json.MarshalIndent(tokenStats, "", "  ")
	tokenStatsMu.Unlock()
	if err != nil {
		return
	}
	os.WriteFile(tokenStatsPath, data, 0644)
}

func recordTokenUsage(model string, promptTokens, completionTokens, totalTokens int64) {
	tokenStatsMu.Lock()
	tokenStats.TotalRequests++
	ms, ok := tokenStats.Models[model]
	if !ok {
		ms = &ModelStats{}
		tokenStats.Models[model] = ms
	}
	ms.RequestCount++
	ms.PromptTokens += promptTokens
	ms.CompletionTokens += completionTokens
	ms.TotalTokens += totalTokens
	tokenStatsMu.Unlock()
	go saveTokenStats()
}

// ======================== Thinking/Reasoning 判断 ========================

func isThinkingEnabled(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		t, _ := v["type"].(string)
		return t == "enabled"
	case bool:
		return v
	default:
		return false
	}
}

func isThinkingDisabled(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		t, _ := v["type"].(string)
		return t == "disabled"
	case bool:
		return !v
	default:
		return false
	}
}

func wantsReasoning(req *OpenAIRequest) bool {
	if getForceDisableThinking() {
		return false
	}
	if isThinkingDisabled(req.Thinking) {
		return false
	}
	if isThinkingEnabled(req.Thinking) {
		return true
	}
	if req.ExtraBody != nil {
		if isThinkingDisabled(req.ExtraBody["thinking"]) {
			return false
		}
		if isThinkingEnabled(req.ExtraBody["thinking"]) {
			return true
		}
	}
	return true
}

// ======================== 消息处理 ========================

func normalizeContent(content any) *string {
	if content == nil {
		return nil
	}
	switch v := content.(type) {
	case string:
		return &v
	case []any:
		var parts []string
		for _, part := range v {
			if p, ok := part.(map[string]any); ok {
				if text, ok := p["text"].(string); ok {
					parts = append(parts, text)
					continue
				}
				if text, ok := p["content"].(string); ok {
					parts = append(parts, text)
					continue
				}
			}
			if text, ok := part.(string); ok {
				parts = append(parts, text)
			}
		}
		joined := strings.Join(parts, "\n")
		return &joined
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		s := string(b)
		return &s
	}
}

func fixToolCallGaps(messages []Message) []Message {
	toolResponses := map[string]*Message{}
	for i := range messages {
		if messages[i].Role == "tool" && messages[i].ToolCallID != "" {
			toolResponses[messages[i].ToolCallID] = &messages[i]
		}
	}
	fixed := make([]Message, 0, len(messages)+len(messages)/4)
	emitted := map[string]bool{}
	for _, msg := range messages {
		if msg.Role == "tool" && msg.ToolCallID != "" {
			if emitted[msg.ToolCallID] {
				continue
			}
		}
		fixed = append(fixed, msg)
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				if resp, found := toolResponses[tc.ID]; found {
					fixed = append(fixed, *resp)
				} else {
					fixed = append(fixed, Message{Role: "tool", ToolCallID: tc.ID, Content: "Tool call result not available"})
				}
				emitted[tc.ID] = true
			}
		}
	}
	return fixed
}

func ensureReasoningContent(messages []Message, thinking bool) []Message {
	if !thinking {
		return messages
	}
	for i := range messages {
		if messages[i].Role == "assistant" && messages[i].ReasoningContent == nil {
			empty := ""
			messages[i].ReasoningContent = &empty
		}
	}
	return messages
}

func convertMessagesForUpstream(messages []Message) []map[string]any {
	converted := make([]map[string]any, 0, len(messages))
	for _, msg := range messages {
		clean := map[string]any{}
		if msg.Role != "" {
			clean["role"] = msg.Role
		}
		content := normalizeContent(msg.Content)
		reasoningContent := msg.ReasoningContent
		if content != nil {
			clean["content"] = *content
		}
		if reasoningContent != nil {
			clean["reasoning_content"] = *reasoningContent
		}
		if len(msg.ToolCalls) > 0 {
			clean["tool_calls"] = msg.ToolCalls
		}
		if msg.ToolCallID != "" {
			clean["tool_call_id"] = msg.ToolCallID
		}
		if msg.Name != "" {
			clean["name"] = msg.Name
		}
		converted = append(converted, clean)
	}
	return converted
}

// ======================== 完整请求转换（含 thinking/reasoning_effort/ExtraBody） ========================

func convertRequest(req *OpenAIRequest) map[string]any {
	converted := map[string]any{
		"model":    req.Model,
		"messages": convertMessagesForUpstream(req.Messages),
		"stream":   req.Stream,
	}
	if req.Temperature != nil {
		converted["temperature"] = *req.Temperature
	}
	if req.MaxTokens != 0 {
		converted["max_tokens"] = req.MaxTokens
	}
	if req.TopP != nil {
		converted["top_p"] = *req.TopP
	}
	if len(req.Tools) > 0 {
		converted["tools"] = req.Tools
	}
	if req.ToolChoice != nil {
		converted["tool_choice"] = req.ToolChoice
	}
	// 处理思维模式
	if getForceDisableThinking() || isThinkingDisabled(req.Thinking) {
		converted["thinking"] = map[string]string{"type": "disabled"}
	} else {
		converted["thinking"] = map[string]string{"type": "enabled"}
	}
	// 处理 reasoning_effort
	if !getForceDisableThinking() && req.ReasoningEffort != "" {
		effortMap := getReasoningEffortMap()
		if mapped, ok := effortMap[req.ReasoningEffort]; ok {
			converted["reasoning_effort"] = mapped
		} else {
			converted["reasoning_effort"] = req.ReasoningEffort
		}
	}
	// 合并 ExtraBody
	if req.ExtraBody != nil {
		for k, v := range req.ExtraBody {
			if _, exists := converted[k]; !exists {
				converted[k] = v
			}
		}
	}
	return converted
}

func buildUpstreamBody(req *OpenAIRequest) []byte {
	converted := convertRequest(req)
	b, err := json.Marshal(converted)
	if err != nil {
		log.Printf("Error marshaling upstream body: %v", err)
	}
	return b
}

// ======================== Anthropic 格式兼容 ========================

func isAnthropicFormat(body []byte) bool {
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		if typ, _ := obj["type"].(string); typ == "message" {
			return true
		}
	}
	lines := bytes.Split(body, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		typ, _ := event["type"].(string)
		switch typ {
		case "message_start", "content_block_start", "content_block_delta",
			"content_block_stop", "message_delta", "message_stop", "ping":
			return true
		}
		return false
	}
	return false
}

func parseAnthropicSSE(body []byte) (map[string]any, string, []map[string]any) {
	lines := bytes.Split(body, []byte("\n"))
	var anthropicMsg map[string]any
	var textBuilder, currentToolInputBuilder strings.Builder
	var currentToolUse map[string]any
	var toolUseBlocks []map[string]any
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		typ, _ := event["type"].(string)
		switch typ {
		case "message_start":
			if m, ok := event["message"].(map[string]any); ok {
				anthropicMsg = m
			}
		case "content_block_start":
			if cb, ok := event["content_block"].(map[string]any); ok {
				if cbType, _ := cb["type"].(string); cbType == "tool_use" {
					currentToolUse = cb
					currentToolInputBuilder.Reset()
				}
			}
		case "content_block_delta":
			if delta, ok := event["delta"].(map[string]any); ok {
				if t, ok := delta["text"].(string); ok {
					textBuilder.WriteString(t)
				}
				if dt, _ := delta["type"].(string); dt == "input_json_delta" {
					if partial, ok := delta["partial_json"].(string); ok {
						currentToolInputBuilder.WriteString(partial)
					}
				}
			}
		case "content_block_stop":
			if currentToolUse != nil {
				inputStr := currentToolInputBuilder.String()
				var input any = inputStr
				var parsed any
				if json.Unmarshal([]byte(inputStr), &parsed) == nil {
					input = parsed
				}
				currentToolUse["input"] = input
				toolUseBlocks = append(toolUseBlocks, currentToolUse)
				currentToolUse = nil
			}
		case "message_delta":
			if delta, ok := event["delta"].(map[string]any); ok {
				if anthropicMsg == nil {
					anthropicMsg = map[string]any{}
				}
				if stop, ok := delta["stop_reason"].(string); ok {
					anthropicMsg["stop_reason"] = stop
				}
				if usage, ok := delta["usage"].(map[string]any); ok {
					anthropicMsg["usage"] = usage
				}
			}
		case "message_stop":
		case "error":
			return nil, "", nil
		}
	}
	return anthropicMsg, textBuilder.String(), toolUseBlocks
}

func buildOpenAIResponse(anthropicMsg map[string]any, text string, toolUseBlocks []map[string]any, modelID string) []byte {
	if anthropicMsg == nil {
		return nil
	}
	now := time.Now().Unix()
	role, _ := anthropicMsg["role"].(string)
	if role == "" {
		role = "assistant"
	}
	finishReason, _ := anthropicMsg["stop_reason"].(string)
	if finishReason == "tool_use" {
		finishReason = "tool_calls"
	}
	choice := map[string]any{
		"index":         0,
		"message":       map[string]any{"role": role, "content": text},
		"finish_reason": finishReason,
	}
	if len(toolUseBlocks) > 0 {
		var toolCalls []map[string]any
		for _, tb := range toolUseBlocks {
			toolInput := tb["input"]
			argsJSON, _ := json.Marshal(toolInput)
			toolCalls = append(toolCalls, map[string]any{
				"id":   tb["id"],
				"type": "function",
				"function": map[string]any{
					"name":      tb["name"],
					"arguments": string(argsJSON),
				},
			})
		}
		choice["message"].(map[string]any)["tool_calls"] = toolCalls
		if text == "" {
			choice["message"].(map[string]any)["content"] = nil
		}
	}
	resp := map[string]any{
		"id":      anthropicMsg["id"],
		"object":  "chat.completion",
		"created": now,
		"model":   modelID,
		"choices": []map[string]any{choice},
	}
	if usage, ok := anthropicMsg["usage"]; ok {
		resp["usage"] = usage
	}
	result, _ := json.Marshal(resp)
	return result
}

func convertAnthropicMessageToOpenAI(msg map[string]any, modelID string) []byte {
	if msg["model"] == nil {
		msg["model"] = modelID
	}
	var textBuilder strings.Builder
	var toolUses []map[string]any
	if content, ok := msg["content"].([]any); ok {
		for _, c := range content {
			if block, ok := c.(map[string]any); ok {
				switch block["type"] {
				case "text":
					if t, ok := block["text"].(string); ok {
						textBuilder.WriteString(t)
					}
				case "tool_use":
					toolUses = append(toolUses, block)
				}
			}
		}
	}
	return buildOpenAIResponse(msg, textBuilder.String(), toolUses, modelID)
}

func convertAnthropicToOpenAI(body []byte, modelID string) []byte {
	var singleMsg map[string]any
	if json.Unmarshal(body, &singleMsg) == nil {
		if typ, _ := singleMsg["type"].(string); typ == "message" {
			return convertAnthropicMessageToOpenAI(singleMsg, modelID)
		}
	}
	msg, text, toolUses := parseAnthropicSSE(body)
	if msg == nil {
		return body
	}
	if msg["model"] == nil {
		msg["model"] = modelID
	}
	return buildOpenAIResponse(msg, text, toolUses, modelID)
}

// ======================== 响应清理 ========================

func cleanNulls(m map[string]any) {
	for k, v := range m {
		if v == nil {
			delete(m, k)
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			delete(m, k)
		}
	}
}

func cleanStreamDelta(delta map[string]any, keepReasoning bool) {
	if v, ok := delta["content"]; ok && v == nil {
		delete(delta, "content")
	}
	if s, ok := delta["content"].(string); ok && s == "" {
		delete(delta, "content")
	}
	if !keepReasoning {
		delete(delta, "reasoning_content")
	} else {
		if v, ok := delta["reasoning_content"]; ok && v == nil {
			delete(delta, "reasoning_content")
		}
		if s, ok := delta["reasoning_content"].(string); ok && s == "" {
			delete(delta, "reasoning_content")
		}
	}
	if s, ok := delta["role"].(string); ok && s == "" {
		delete(delta, "role")
	}
}

// convertStreamChunkWithUsage 转换流式 chunk 并同时提取 usage，避免二次解析
func convertStreamChunkWithUsage(line string, keepReasoning bool) (string, map[string]any) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
		return line, nil
	}
	if !strings.HasPrefix(line, "data: ") {
		return line, nil
	}
	data := line[6:]
	var raw map[string]any
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return line, nil
	}

	// 提取 usage
	var usage map[string]any
	if u, ok := raw["usage"].(map[string]any); ok {
		usage = u
	}

	choices, ok := raw["choices"].([]any)
	if !ok || len(choices) == 0 {
		return "", usage
	}
	for i, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if delta, ok := choice["delta"].(map[string]any); ok {
			cleanStreamDelta(delta, keepReasoning)
			choice["delta"] = delta
		}
		if msg, ok := choice["message"].(map[string]any); ok {
			cleanNulls(msg)
			if !keepReasoning {
				delete(msg, "reasoning_content")
			}
			choice["message"] = msg
		}
		if v, ok := choice["logprobs"]; ok && v == nil {
			delete(choice, "logprobs")
		}
		if v, ok := choice["finish_reason"]; ok && v == nil {
			delete(choice, "finish_reason")
		}
		if s, ok := choice["finish_reason"].(string); ok && s == "" {
			delete(choice, "finish_reason")
		}
		choices[i] = choice
	}
	raw["choices"] = choices
	if v, ok := raw["usage"]; ok && v == nil {
		delete(raw, "usage")
	}
	delete(raw, "cost")
	converted, err := json.Marshal(raw)
	if err != nil {
		return line, usage
	}
	return "data: " + string(converted), usage
}

func convertResponse(data []byte, keepReasoning bool) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("Warning: convertResponse unmarshal failed: %v", err)
		return data, nil
	}
	if choices, ok := raw["choices"].([]any); ok {
		for i, c := range choices {
			if choice, ok := c.(map[string]any); ok {
				if msg, ok := choice["message"].(map[string]any); ok {
					cleanNulls(msg)
					if !keepReasoning {
						delete(msg, "reasoning_content")
					}
					choice["message"] = msg
				}
				if v, ok := choice["logprobs"]; ok && v == nil {
					delete(choice, "logprobs")
				}
				choices[i] = choice
			}
		}
		raw["choices"] = choices
	}
	if usage, ok := raw["usage"].(map[string]any); ok {
		cleanU := map[string]any{
			"prompt_tokens":     usage["prompt_tokens"],
			"completion_tokens": usage["completion_tokens"],
			"total_tokens":      usage["total_tokens"],
		}
		raw["usage"] = cleanU
	}
	delete(raw, "cost")
	delete(raw, "system_fingerprint")
	return json.Marshal(raw)
}

// ======================== OpenCode 上游调用 ========================

func buildOCRequest(modelID string, bodyMap map[string]any) (*http.Request, error) {
	bodyMap["model"] = modelID
	delete(bodyMap, "reasoning_effort")
	tryBody, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", "https://opencode.ai/zen/v1/chat/completions", bytes.NewReader(tryBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer public")
	req.Header.Set("User-Agent", fmt.Sprintf("opencode/%s", ocClientVer))
	req.Header.Set("x-opencode-client", "cli")
	req.Header.Set("x-opencode-project", ocProjectID)
	req.Header.Set("x-opencode-session", ocSessionID)
	req.Header.Set("x-opencode-request", "req_"+randomString(24))
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func callOpenCodeAPI(upstreamBody []byte, modelID string) ([]byte, int, http.Header, error) {
	initOCSession()
	modelIDs := getModelIDs()
	modelsToTry := []string{modelID}
	for _, m := range modelIDs {
		if m != modelID {
			modelsToTry = append(modelsToTry, m)
		}
	}
	if len(modelsToTry) == 0 {
		modelsToTry = []string{modelID}
	}

	// 循环外解析一次
	var bodyMap map[string]any
	if err := json.Unmarshal(upstreamBody, &bodyMap); err != nil {
		return nil, 500, nil, fmt.Errorf("invalid request body")
	}

	var lastErr error
	for _, tryModel := range modelsToTry {
		up, err := buildOCRequest(tryModel, bodyMap)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := getHTTPClient().Do(up)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			b, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return nil, 0, nil, readErr
			}
			if isAnthropicFormat(b) {
				b = convertAnthropicToOpenAI(b, tryModel)
			}
			return b, resp.StatusCode, resp.Header, nil
		}
		errBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if debugMode {
			log.Printf("[upstream error] model=%s status=%d body=%s", tryModel, resp.StatusCode, string(errBody))
		}
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("upstream error")
			continue
		}
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("upstream error")
	}
	return nil, 500, nil, lastErr
}

func callOpenCodeAPIStream(upstreamBody []byte, modelID string) (io.ReadCloser, int, http.Header, error) {
	initOCSession()
	modelIDs := getModelIDs()
	modelsToTry := []string{modelID}
	for _, m := range modelIDs {
		if m != modelID {
			modelsToTry = append(modelsToTry, m)
		}
	}
	if len(modelsToTry) == 0 {
		modelsToTry = []string{modelID}
	}

	// 循环外解析一次
	var bodyMap map[string]any
	if err := json.Unmarshal(upstreamBody, &bodyMap); err != nil {
		return nil, 500, nil, fmt.Errorf("invalid request body")
	}

	for _, tryModel := range modelsToTry {
		up, err := buildOCRequest(tryModel, bodyMap)
		if err != nil {
			continue
		}
		resp, err := getHTTPClient().Do(up)
		if err != nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp.Body, resp.StatusCode, resp.Header, nil
		}
		errBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if debugMode {
			log.Printf("[upstream error] model=%s status=%d body=%s", tryModel, resp.StatusCode, string(errBody))
		}
		if resp.StatusCode >= 500 {
			continue
		}
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("upstream error")
	}
	return nil, 500, nil, fmt.Errorf("all models failed")
}

// ======================== 安全响应头过滤 ========================

var safeResponseHeaders = map[string]bool{
	"Content-Type":   true,
	"X-RateLimit-Limit":     true,
	"X-RateLimit-Remaining": true,
	"X-RateLimit-Reset":     true,
}

func filterResponseHeaders(h http.Header) http.Header {
	filtered := make(http.Header)
	for k, v := range h {
		if safeResponseHeaders[k] {
			filtered[k] = v
		}
	}
	return filtered
}

// ======================== Chat Completions Handler ========================

// ======================== API Key 认证中间件 ========================

	var authBypassPaths = map[string]bool{
		"/health": true,
		"/admin":  true,
	}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configMu.RLock()
		key := apiKey
		configMu.RUnlock()
		if key == "" || authBypassPaths[r.URL.Path] {
			next(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			auth = r.URL.Query().Get("api_key")
			if auth != "" {
				auth = "Bearer " + auth
			}
		}
		if auth != "Bearer "+key {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized", "message": "需要有效的 API Key（在 Authorization 请求头中传入 Bearer token）"})
			return
		}
		next(w, r)
	}
}

func chatCompletionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/chat/completions\n%s", cnt, string(body))
	}

	var req OpenAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	req.Model = resolveModel(req.Model)
	if req.Model == "" {
		modelIDs := getModelIDs()
		if len(modelIDs) > 0 {
			req.Model = modelIDs[0]
		} else {
			req.Model = "deepseek-v4-flash-free"
		}
	}
	req.Messages = fixToolCallGaps(req.Messages)
	keepReasoning := wantsReasoning(&req)
	req.Messages = ensureReasoningContent(req.Messages, keepReasoning)
	upstreamBody := buildUpstreamBody(&req)

	if req.Stream {
		upResp, status, _, err := callOpenCodeAPIStream(upstreamBody, req.Model)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
			return
		}
		defer upResp.Close()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		reader := bufio.NewReader(upResp)
		doneSeen := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Printf("Error reading stream: %v", err)
				// 发送错误事件通知客户端
				w.Write([]byte("data: {\"error\":\"stream read error\"}\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				return
			}
			if doneSeen {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "data: [DONE]" {
				doneSeen = true
				w.Write([]byte("data: [DONE]\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				continue
			}

			out, usage := convertStreamChunkWithUsage(line, keepReasoning)
			if out == "" {
				// 空choices chunk，但可能有 usage
				if usage != nil {
					pt, _ := usage["prompt_tokens"].(float64)
					ct, _ := usage["completion_tokens"].(float64)
					tt, _ := usage["total_tokens"].(float64)
					if tt > 0 {
						recordTokenUsage(req.Model, int64(pt), int64(ct), int64(tt))
					}
				}
				continue
			}

			// 提取 usage（已在 convertStreamChunkWithUsage 中解析）
			if usage != nil && !doneSeen {
				pt, _ := usage["prompt_tokens"].(float64)
				ct, _ := usage["completion_tokens"].(float64)
				tt, _ := usage["total_tokens"].(float64)
				if tt > 0 {
					recordTokenUsage(req.Model, int64(pt), int64(ct), int64(tt))
				}
			}

			w.Write([]byte(out))
			w.Write([]byte("\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		return
	}

	respBody, status, _, err := callOpenCodeAPI(upstreamBody, req.Model)
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
		return
	}
	outBody := respBody
	convertedResp, err := convertResponse(respBody, keepReasoning)
	if err == nil {
		outBody = convertedResp
	}
	// Record token usage
	var usageResp map[string]any
	if json.Unmarshal(respBody, &usageResp) == nil {
		if u, ok := usageResp["usage"].(map[string]any); ok {
			pt, _ := u["prompt_tokens"].(float64)
			ct, _ := u["completion_tokens"].(float64)
			tt, _ := u["total_tokens"].(float64)
			if tt > 0 {
				recordTokenUsage(req.Model, int64(pt), int64(ct), int64(tt))
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(outBody)
}

// ======================== Models Handler ========================

func listModelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	modelMu.RLock()
	loaded, models := modelsLoaded, modelsCache
	modelMu.RUnlock()
	if !loaded || len(models) == 0 {
		fetched, err := fetchModels()
		if err == nil && len(fetched) > 0 {
			modelMu.Lock()
			modelsCache = fetched
			modelsLoaded = true
			models = modelsCache
			modelMu.Unlock()
		}
	}
	if len(models) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "无法获取模型列表，请检查上游服务是否可用",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"object": "list",
		"data":   models,
	})
}

// ======================== Claude Messages API ========================

func extractClaudeSystemText(system any) string {
	if system == nil {
		return ""
	}
	switch v := system.(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			if block, ok := item.(map[string]any); ok {
				if block["type"] == "text" {
					if text, ok := block["text"].(string); ok {
						parts = append(parts, text)
					}
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func cleanJsonSchema(schema any) any {
	m, ok := schema.(map[string]any)
	if !ok {
		return schema
	}
	delete(m, "$schema")
	delete(m, "title")
	delete(m, "examples")
	delete(m, "additionalProperties")
	if m["type"] == "string" {
		delete(m, "format")
	}
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			m[k] = cleanJsonSchema(sub)
		}
		if arr, ok := v.([]any); ok {
			for i, elem := range arr {
				if sub, ok := elem.(map[string]any); ok {
					arr[i] = cleanJsonSchema(sub)
				}
			}
			m[k] = arr
		}
	}
	return m
}

func claudeToOpenAIMessages(claudeMsgs []ClaudeMessage, system any) []Message {
	var messages []Message
	if sysText := extractClaudeSystemText(system); sysText != "" {
		messages = append(messages, Message{Role: "system", Content: sysText})
	}
	for _, msg := range claudeMsgs {
		switch content := msg.Content.(type) {
		case string:
			messages = append(messages, Message{Role: msg.Role, Content: content})
		case []any:
			var textParts []string
			var reasoningParts []string
			var toolCalls []ToolCall
			var toolResults []Message
			for _, item := range content {
				block, ok := item.(map[string]any)
				if !ok {
					continue
				}
				blockType, _ := block["type"].(string)
				switch blockType {
				case "text":
					if text, ok := block["text"].(string); ok && text != "" {
						textParts = append(textParts, text)
					}
				case "thinking":
					if thinking, ok := block["thinking"].(string); ok && thinking != "" {
						reasoningParts = append(reasoningParts, thinking)
					}
				case "tool_use":
					id, _ := block["id"].(string)
					name, _ := block["name"].(string)
					var args string
					switch input := block["input"].(type) {
					case string:
						args = input
					default:
						if input != nil {
							b, _ := json.Marshal(input)
							args = string(b)
						}
					}
					if args == "" {
						args = "{}"
					}
					toolCalls = append(toolCalls, ToolCall{
						ID:   id,
						Type: "function",
						Function: FunctionCall{
							Name:      name,
							Arguments: args,
						},
					})
				case "tool_result":
					toolUseID, _ := block["tool_use_id"].(string)
					var resultText string
					switch c := block["content"].(type) {
					case string:
						resultText = c
					case []any:
						var parts []string
						for _, p := range c {
							if pb, ok := p.(map[string]any); ok && pb["type"] == "text" {
								if t, ok := pb["text"].(string); ok {
									parts = append(parts, t)
								}
							}
						}
						resultText = strings.Join(parts, "\n")
					default:
						if c != nil {
							b, _ := json.Marshal(c)
							resultText = string(b)
						}
					}
					toolResults = append(toolResults, Message{
						Role:       "tool",
						ToolCallID: toolUseID,
						Content:    resultText,
					})
				}
			}
			om := Message{Role: msg.Role}
			if len(textParts) > 0 {
				om.Content = strings.Join(textParts, "\n")
			} else if len(toolCalls) == 0 {
				om.Content = ""
			}
			if len(reasoningParts) > 0 {
				rc := strings.Join(reasoningParts, "\n")
				om.ReasoningContent = &rc
			}
			if len(toolCalls) > 0 {
				om.ToolCalls = toolCalls
			}
			messages = append(messages, om)
			messages = append(messages, toolResults...)
		default:
			b, _ := json.Marshal(content)
			messages = append(messages, Message{Role: msg.Role, Content: string(b)})
		}
	}
	return messages
}

func claudeToOpenAITools(claudeTools []ClaudeTool) []Tool {
	tools := make([]Tool, 0, len(claudeTools))
	for _, ct := range claudeTools {
		params := ct.InputSchema
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		params = cleanJsonSchema(params)
		tools = append(tools, Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        ct.Name,
				Description: ct.Description,
				Parameters:  params.(map[string]any),
			},
		})
	}
	return tools
}

func openAIToClaudeResponse(chatBody []byte, model string, wantReasoning bool) []byte {
	var chat struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Created int64  `json:"created"`
		Choices []struct {
			Message struct {
				Content          string     `json:"content"`
				ReasoningContent string     `json:"reasoning_content"`
				ToolCalls        []ToolCall `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(chatBody, &chat); err != nil {
		log.Printf("Warning: openAIToClaudeResponse unmarshal failed: %v", err)
	}

	content := []ClaudeContent{}
	stopReason := "end_turn"

	if len(chat.Choices) > 0 {
		msg := chat.Choices[0].Message
		fr := chat.Choices[0].FinishReason
		if wantReasoning && msg.ReasoningContent != "" {
			content = append(content, ClaudeContent{
				Type:     "thinking",
				Thinking: msg.ReasoningContent,
			})
		}
		if msg.Content != "" {
			content = append(content, ClaudeContent{
				Type: "text",
				Text: msg.Content,
			})
		}
		for _, tc := range msg.ToolCalls {
			var input any
			json.Unmarshal([]byte(tc.Function.Arguments), &input)
			if input == nil {
				input = map[string]any{}
			}
			content = append(content, ClaudeContent{
				Type:  "tool_use",
				ID:    tc.ID,
				Name:  tc.Function.Name,
				Input: input,
			})
		}
		switch fr {
		case "stop":
			stopReason = "end_turn"
		case "length":
			stopReason = "max_tokens"
		case "tool_calls", "function_call":
			stopReason = "tool_use"
		}
	}

	if len(content) == 0 {
		content = append(content, ClaudeContent{Type: "text", Text: ""})
	}

	resp := ClaudeResponse{
		ID:         fmt.Sprintf("msg_%s", randomString(24)),
		Type:       "message",
		Role:       "assistant",
		Content:    content,
		Model:      model,
		StopReason: stopReason,
	}
	if chat.Usage != nil {
		inputTokens, _ := chat.Usage["prompt_tokens"]
		outputTokens, _ := chat.Usage["completion_tokens"]
		resp.Usage = &ClaudeUsage{
			InputTokens:  int(toFloat64(inputTokens)),
			OutputTokens: int(toFloat64(outputTokens)),
		}
	}
	result, _ := json.Marshal(resp)
	return result
}

func toFloat64(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

func claudeMessagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/messages\n%s", cnt, string(body))
	}

	var claudeReq ClaudeRequest
	if err := json.Unmarshal(body, &claudeReq); err != nil {
		http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"Invalid JSON"}}`, http.StatusBadRequest)
		return
	}
	claudeReq.Model = resolveModel(claudeReq.Model)

	messages := claudeToOpenAIMessages(claudeReq.Messages, claudeReq.System)
	messages = fixToolCallGaps(messages)

	chatReq := OpenAIRequest{
		Model:    claudeReq.Model,
		Messages: messages,
		Stream:   claudeReq.Stream,
	}
	if claudeReq.MaxTokens > 0 {
		chatReq.MaxTokens = claudeReq.MaxTokens
	}
	if claudeReq.Temperature != nil {
		chatReq.Temperature = claudeReq.Temperature
	}
	if claudeReq.TopP != nil {
		chatReq.TopP = claudeReq.TopP
	}
	if len(claudeReq.Tools) > 0 {
		chatReq.Tools = claudeToOpenAITools(claudeReq.Tools)
		chatReq.ToolChoice = "auto"
	}

	wantReasoning := !getForceDisableThinking()
	if claudeReq.Thinking != nil {
		if isThinkingDisabled(claudeReq.Thinking) {
			wantReasoning = false
		}
	}
	keepReasoning := wantReasoning
	chatReq.Messages = ensureReasoningContent(chatReq.Messages, keepReasoning)

	upstreamBody := buildUpstreamBody(&chatReq)

	if claudeReq.Stream {
		upResp, status, _, err := callOpenCodeAPIStream(upstreamBody, chatReq.Model)
		if err != nil || status < 200 || status >= 300 {
			errResp := map[string]any{
				"type":  "error",
				"error": map[string]string{"type": "api_error", "message": "upstream error"},
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(errResp)
			return
		}
		defer upResp.Close()
		claudeStreamHandler(w, upResp, claudeReq.Model, keepReasoning)
		return
	}

	respBody, status, _, err := callOpenCodeAPI(upstreamBody, chatReq.Model)
	if err != nil || status < 200 || status >= 300 {
		errResp := map[string]any{
			"type":  "error",
			"error": map[string]string{"type": "api_error", "message": "upstream error"},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(errResp)
		return
	}

	claudeRespBody := openAIToClaudeResponse(respBody, claudeReq.Model, wantReasoning)

	// Record token usage
	var usageResp map[string]any
	if json.Unmarshal(respBody, &usageResp) == nil {
		if u, ok := usageResp["usage"].(map[string]any); ok {
			pt, _ := u["prompt_tokens"].(float64)
			ct, _ := u["completion_tokens"].(float64)
			tt, _ := u["total_tokens"].(float64)
			if tt > 0 {
				recordTokenUsage(claudeReq.Model, int64(pt), int64(ct), int64(tt))
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if debugMode {
		log.Printf("[client response]\n%s", string(claudeRespBody))
	}
	w.Write(claudeRespBody)
}

func claudeStreamHandler(w http.ResponseWriter, respBody io.ReadCloser, model string, keepReasoning bool) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(respBody)

	msgID := fmt.Sprintf("msg_%s", randomString(24))
	blockIndex := 0
	thinkingBlockOpen := false
	textBlockOpen := false
	toolCallAccumulator := map[int]map[string]string{}
	toolCallOrder := []int{}
	messageStartSent := false
	fullUsage := map[string]any{}
	defer func() {
		if len(fullUsage) > 0 {
			pt, _ := fullUsage["prompt_tokens"].(float64)
			ct, _ := fullUsage["completion_tokens"].(float64)
			tt, _ := fullUsage["total_tokens"].(float64)
			if tt > 0 {
				recordTokenUsage(model, int64(pt), int64(ct), int64(tt))
			}
		}
	}()

	emitClaudeEvent := func(event string, data any) {
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Printf("Error marshaling Claude SSE event: %v", err)
			return
		}
		w.Write([]byte("event: " + event + "\n"))
		w.Write([]byte("data: " + string(jsonData) + "\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	closeThinkingBlock := func() {
		if !thinkingBlockOpen {
			return
		}
		emitClaudeEvent("content_block_stop", map[string]any{
			"type":          "content_block_stop",
			"index":         blockIndex - 1,
			"content_block": map[string]any{"type": "thinking"},
		})
		thinkingBlockOpen = false
	}

	closeTextBlock := func() {
		if !textBlockOpen {
			return
		}
		emitClaudeEvent("content_block_stop", map[string]any{
			"type":          "content_block_stop",
			"index":         blockIndex - 1,
			"content_block": map[string]any{"type": "text"},
		})
		textBlockOpen = false
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading stream: %v", err)
			break
		}
		if debugMode && strings.HasPrefix(line, "data: ") {
			log.Printf("[upstream raw chunk] %s", strings.TrimSpace(line[6:]))
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var chunk map[string]any
		if err := json.Unmarshal([]byte(line[6:]), &chunk); err != nil {
			continue
		}

		choices, ok := chunk["choices"].([]any)
		if !ok || len(choices) == 0 {
			if usage, ok := chunk["usage"].(map[string]any); ok {
				fullUsage = usage
			}
			continue
		}

		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		finishReason, _ := choice["finish_reason"].(string)

		if !messageStartSent {
			messageStartSent = true
			emitClaudeEvent("message_start", map[string]any{
				"type": "message_start",
				"message": map[string]any{
					"id":          msgID,
					"type":        "message",
					"role":        "assistant",
					"content":     []any{},
					"model":       model,
					"stop_reason": nil,
					"usage":       map[string]any{"input_tokens": 0, "output_tokens": 0},
				},
			})
			emitClaudeEvent("ping", map[string]any{"type": "ping"})
		}

		if rc, ok := delta["reasoning_content"]; ok && keepReasoning {
			rcStr, _ := rc.(string)
			if rcStr != "" {
				closeTextBlock()
				if !thinkingBlockOpen {
					emitClaudeEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": blockIndex,
						"content_block": map[string]any{
							"type":     "thinking",
							"thinking": "",
						},
					})
					thinkingBlockOpen = true
					blockIndex++
				}
				emitClaudeEvent("content_block_delta", map[string]any{
					"type":  "content_block_delta",
					"index": blockIndex - 1,
					"delta": map[string]any{
						"type":     "thinking_delta",
						"thinking": rcStr,
					},
				})
			}
		}

		if c, ok := delta["content"]; ok && c != nil {
			contentStr, _ := c.(string)
			if contentStr != "" {
				closeThinkingBlock()
				if !textBlockOpen {
					emitClaudeEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": blockIndex,
						"content_block": map[string]any{
							"type": "text",
							"text": "",
						},
					})
					textBlockOpen = true
					blockIndex++
				}
				emitClaudeEvent("content_block_delta", map[string]any{
					"type":  "content_block_delta",
					"index": blockIndex - 1,
					"delta": map[string]any{
						"type": "text_delta",
						"text": contentStr,
					},
				})
			}
		}

		if rawToolCalls, ok := delta["tool_calls"].([]any); ok {
			for _, rawTC := range rawToolCalls {
				tc, ok := rawTC.(map[string]any)
				if !ok {
					continue
				}
				idxFloat, _ := tc["index"].(float64)
				upstreamIndex := int(idxFloat)

				closeThinkingBlock()
				closeTextBlock()

				if _, exists := toolCallAccumulator[upstreamIndex]; !exists {
					callID, _ := tc["id"].(string)
					if callID == "" {
						callID = "toolu_" + randomString(12)
					}
					fn, _ := tc["function"].(map[string]any)
					name, _ := fn["name"].(string)
					toolCallAccumulator[upstreamIndex] = map[string]string{
						"id":   callID,
						"name": name,
						"args": "",
					}
					toolCallOrder = append(toolCallOrder, upstreamIndex)
					emitClaudeEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": blockIndex,
						"content_block": map[string]any{
							"type":  "tool_use",
							"id":    callID,
							"name":  name,
							"input": map[string]any{},
						},
					})
					blockIndex++
				}

				fn, _ := tc["function"].(map[string]any)
				if argDelta, ok := fn["arguments"].(string); ok && argDelta != "" {
					toolCallAccumulator[upstreamIndex]["args"] += argDelta
					emitClaudeEvent("content_block_delta", map[string]any{
						"type":  "content_block_delta",
						"index": blockIndex - 1,
						"delta": map[string]any{
							"type":          "input_json_delta",
							"partial_json": argDelta,
						},
					})
				}
			}
		}

		if usage, ok := chunk["usage"].(map[string]any); ok {
			fullUsage = usage
		}

		if finishReason == "stop" || finishReason == "length" || finishReason == "tool_calls" || finishReason == "function_call" || finishReason == "content_filter" {
			closeThinkingBlock()
			closeTextBlock()

			for _, idx := range toolCallOrder {
				acc := toolCallAccumulator[idx]
				emitClaudeEvent("content_block_stop", map[string]any{
					"type":  "content_block_stop",
					"index": blockIndex - len(toolCallOrder) + indexOfInt(toolCallOrder, idx),
					"content_block": map[string]any{
						"type":  "tool_use",
						"id":    acc["id"],
						"name":  acc["name"],
						"input": map[string]any{},
					},
				})
			}

			stopReason := "end_turn"
			switch finishReason {
			case "length":
				stopReason = "max_tokens"
			case "tool_calls", "function_call":
				stopReason = "tool_use"
			}

			usage := map[string]any{}
			if len(fullUsage) > 0 {
				usage["input_tokens"] = fullUsage["prompt_tokens"]
				usage["output_tokens"] = fullUsage["completion_tokens"]
			} else {
				usage["input_tokens"] = 0
				usage["output_tokens"] = 0
			}

			emitClaudeEvent("message_delta", map[string]any{
				"type": "message_delta",
				"delta": map[string]any{
					"stop_reason": stopReason,
				},
				"usage": map[string]any{
					"output_tokens": usage["output_tokens"],
				},
			})
			emitClaudeEvent("message_stop", map[string]any{
				"type": "message_stop",
			})
			return
		}
	}

	closeThinkingBlock()
	closeTextBlock()
	emitClaudeEvent("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn"},
		"usage": map[string]any{"output_tokens": 0},
	})
	emitClaudeEvent("message_stop", map[string]any{"type": "message_stop"})
}

func indexOfInt(slice []int, val int) int {
	for i, v := range slice {
		if v == val {
			return i
		}
	}
	return 0
}

// ======================== Responses API ========================

func responsesInputToMessages(input any, instructions string) []Message {
	var messages []Message
	if instructions != "" {
		messages = append(messages, Message{Role: "system", Content: instructions})
	}
	switch v := input.(type) {
	case string:
		messages = append(messages, Message{Role: "user", Content: v})
	case []any:
		functionOutputs := collectFunctionOutputs(v)
		for _, item := range v {
			switch elem := item.(type) {
			case string:
				messages = append(messages, Message{Role: "user", Content: elem})
			case map[string]any:
				itemType, _ := elem["type"].(string)
				switch itemType {
				case "function_call", "tool_call":
					callID, _ := elem["call_id"].(string)
					if callID == "" {
						callID, _ = elem["id"].(string)
					}
					name, _ := elem["name"].(string)
					args, _ := elem["arguments"].(string)
					if name == "" {
						if tu, ok := elem["tool_use"].(map[string]any); ok {
							name, _ = tu["name"].(string)
							callID, _ = tu["id"].(string)
							if a, ok := tu["arguments"].(string); ok {
								args = a
							} else if inp, ok := tu["input"]; ok {
								b, _ := json.Marshal(inp)
								args = string(b)
							}
						}
					}
					if args == "" {
						args = "{}"
					}
					messages = append(messages, Message{
						Role:    "assistant",
						Content: "",
						ToolCalls: []ToolCall{{
							ID:   callID,
							Type: "function",
							Function: FunctionCall{
								Name:      name,
								Arguments: args,
							},
						}},
					})
					if callID != "" {
						output := functionOutputs[callID]
						if output == "" {
							output = "[tool output missing]"
						}
						messages = append(messages, Message{Role: "tool", ToolCallID: callID, Content: output})
					}
				case "function_call_output", "tool_result":
					callID, _ := elem["call_id"].(string)
					if callID == "" {
						callID, _ = elem["tool_use_id"].(string)
					}
					if callID != "" {
						output := functionOutputs[callID]
						if output == "" {
							switch o := elem["output"].(type) {
							case string:
								output = o
							default:
								if o != nil {
									b, _ := json.Marshal(o)
									output = string(b)
								}
							}
						}
						if output == "" {
							output = "[tool output missing]"
						}
						messages = append(messages, Message{Role: "tool", ToolCallID: callID, Content: output})
					}
					continue
				case "reasoning":
					if text := extractTextFromContentParts(elem["summary"]); text != "" {
						messages = append(messages, Message{Role: "assistant", Content: "", ReasoningContent: &text})
					}
					continue
				case "message", "":
					role := "user"
					if r, ok := elem["role"].(string); ok && r != "" {
						role = r
					}
					if role == "developer" {
						role = "system"
					}
					text := extractTextFromContentParts(elem["content"])
					messages = append(messages, Message{Role: role, Content: text})
				default:
					role := "user"
					if r, ok := elem["role"].(string); ok && r != "" {
						role = r
					}
					text := extractTextFromContentParts(elem["content"])
					if text == "" {
						b, _ := json.Marshal(elem)
						text = string(b)
					}
					messages = append(messages, Message{Role: role, Content: text})
				}
			default:
				b, _ := json.Marshal(elem)
				messages = append(messages, Message{Role: "user", Content: string(b)})
			}
		}
	default:
		b, _ := json.Marshal(v)
		messages = append(messages, Message{Role: "user", Content: string(b)})
	}
	return messages
}

func convertResponsesTools(tools []ResponsesTool) []Tool {
	converted := make([]Tool, 0, len(tools))
	for _, tool := range tools {
		if tool.Type != "function" {
			continue
		}
		fn := ToolFunction{
			Name:        tool.Name,
			Description: tool.Description,
			Parameters:  tool.Parameters,
		}
		if tool.Function != nil {
			fn = *tool.Function
		}
		if fn.Parameters == nil {
			fn.Parameters = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		converted = append(converted, Tool{Type: "function", Function: fn})
	}
	return converted
}

func convertResponsesToolChoice(choice any) any {
	if choice == nil {
		return nil
	}
	choiceMap, ok := choice.(map[string]any)
	if !ok {
		return choice
	}
	if choiceMap["type"] == "function" {
		if name, ok := choiceMap["name"].(string); ok && name != "" {
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": name},
			}
		}
	}
	return choice
}

func collectFunctionOutputs(items []any) map[string]string {
	outputs := map[string]string{}
	for _, item := range items {
		elem, ok := item.(map[string]any)
		if !ok || elem["type"] != "function_call_output" {
			continue
		}
		callID, _ := elem["call_id"].(string)
		if callID == "" {
			continue
		}
		switch v := elem["output"].(type) {
		case string:
			outputs[callID] = v
		default:
			b, _ := json.Marshal(v)
			outputs[callID] = string(b)
		}
	}
	return outputs
}

func extractTextFromContentParts(content any) string {
	parts, ok := content.([]any)
	if !ok {
		if s, ok := content.(string); ok {
			return s
		}
		return ""
	}
	var texts []string
	for _, p := range parts {
		if part, ok := p.(map[string]any); ok {
			if part["type"] == "input_text" || part["type"] == "output_text" {
				if t, ok := part["text"].(string); ok {
					texts = append(texts, t)
				}
			}
		}
	}
	return strings.Join(texts, "\n")
}

func responsesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/responses\n%s", cnt, string(body))
	}

	var respReq ResponsesAPIRequest
	if err := json.Unmarshal(body, &respReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	respReq.Model = resolveModel(respReq.Model)
	if respReq.Model == "" {
		modelIDs := getModelIDs()
		if len(modelIDs) > 0 {
			respReq.Model = modelIDs[0]
		} else {
			respReq.Model = "deepseek-v4-flash-free"
		}
	}

	messages := respReq.Messages
	if len(messages) == 0 {
		messages = responsesInputToMessages(respReq.Input, respReq.Instructions)
	} else if respReq.Instructions != "" {
		messages = append([]Message{{Role: "system", Content: respReq.Instructions}}, messages...)
	}

	chatReq := OpenAIRequest{
		Model:    respReq.Model,
		Messages: messages,
		Stream:   respReq.Stream,
	}
	if respReq.Temperature != 0 {
		chatReq.Temperature = &respReq.Temperature
	}
	if respReq.MaxTokens != 0 {
		chatReq.MaxTokens = respReq.MaxTokens
	}
	if respReq.TopP != 0 {
		chatReq.TopP = &respReq.TopP
	}
	if len(respReq.Tools) > 0 {
		chatReq.Tools = convertResponsesTools(respReq.Tools)
	}
	if respReq.ToolChoice != nil {
		chatReq.ToolChoice = convertResponsesToolChoice(respReq.ToolChoice)
	}
	if respReq.ParallelToolCalls != nil {
		chatReq.ExtraBody = map[string]any{"parallel_tool_calls": *respReq.ParallelToolCalls}
	}
	// 将 Responses API reasoning.effort 映射到 Chat Completions
	if !getForceDisableThinking() && respReq.Reasoning.Effort != "" {
		if respReq.Reasoning.Effort != "none" {
			chatReq.ReasoningEffort = respReq.Reasoning.Effort
		}
	}

	wantReasoning := !getForceDisableThinking()
	chatReq.Messages = fixToolCallGaps(chatReq.Messages)
	keepReasoning := wantsReasoning(&chatReq)
	chatReq.Messages = ensureReasoningContent(chatReq.Messages, keepReasoning)

	upstreamBody := buildUpstreamBody(&chatReq)

	if respReq.Stream {
		upResp, status, _, err := callOpenCodeAPIStream(upstreamBody, chatReq.Model)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
			return
		}
		defer upResp.Close()

		resp := &http.Response{
			StatusCode: status,
			Body:       upResp,
			Header:     make(http.Header),
		}
		responsesStreamHandler(w, r, resp, chatReq.Model, chatReq.Model, wantReasoning, chatReq.Tools, chatReq.ToolChoice)
		return
	}

	respBody, status, _, err := callOpenCodeAPI(upstreamBody, chatReq.Model)
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
		return
	}

	responsesBody := convertChatToResponses(respBody, chatReq.Model, wantReasoning, chatReq.Tools, chatReq.ToolChoice)

	var usageResp map[string]any
	if json.Unmarshal(respBody, &usageResp) == nil {
		if u, ok := usageResp["usage"].(map[string]any); ok {
			pt, _ := u["prompt_tokens"].(float64)
			ct, _ := u["completion_tokens"].(float64)
			tt, _ := u["total_tokens"].(float64)
			if tt > 0 {
				recordTokenUsage(chatReq.Model, int64(pt), int64(ct), int64(tt))
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if debugMode {
		log.Printf("[responses response]\n%s", string(responsesBody))
	}
	w.Write(responsesBody)
}

// ======================== Responses Stream Handler ========================

func responsesStreamHandler(w http.ResponseWriter, _ *http.Request, resp *http.Response, model string, _ string, wantReasoning bool, tools []Tool, toolChoice any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(resp.Body)

	responseID := "resp_" + time.Now().Format("20060102150405") + "_" + randomString(8)
	reasoningID := "rs_" + responseID
	msgID := "msg_" + responseID + "_0"
	createdAt := time.Now().Unix()
	seq := 0

	reasoningStarted := false
	reasoningDone := false
	messageStarted := false
	messageDone := false
	fullReasoning := ""
	fullText := ""
	totalUsage := map[string]any{}
	createdSent := false
	toolCalls := map[int]map[string]any{}
	toolOrder := []int{}

	messageOutputIndex := func() int {
		if reasoningStarted {
			return 1
		}
		return 0
	}

	reasoningItem := func(status string) map[string]any {
		item := map[string]any{
			"id":      reasoningID,
			"type":    "reasoning",
			"summary": []any{},
		}
		if status != "" {
			item["status"] = status
		}
		if status == "completed" {
			item["encrypted_content"] = ""
		}
		if fullReasoning != "" {
			item["summary"] = []any{map[string]any{"type": "summary_text", "text": fullReasoning}}
		}
		return item
	}

	messageItem := func(status string) map[string]any {
		content := []any{map[string]any{
			"type":        "output_text",
			"annotations": []any{},
			"logprobs":    []any{},
			"text":        fullText,
		}}
		return map[string]any{
			"id":      msgID,
			"type":    "message",
			"status":  status,
			"content": content,
			"role":    "assistant",
		}
	}

	emitReasoningDone := func() {
		if !reasoningStarted || reasoningDone {
			return
		}
		seq++
		emitSSEEvent(w, flusher, "response.reasoning_summary_text.done", map[string]any{
			"type":            "response.reasoning_summary_text.done",
			"sequence_number": seq,
			"item_id":         reasoningID,
			"output_index":    0,
			"summary_index":   0,
			"text":            fullReasoning,
		})
		seq++
		emitSSEEvent(w, flusher, "response.reasoning_summary_part.done", map[string]any{
			"type":            "response.reasoning_summary_part.done",
			"sequence_number": seq,
			"item_id":         reasoningID,
			"output_index":    0,
			"summary_index":   0,
			"part":            map[string]any{"type": "summary_text", "text": fullReasoning},
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    0,
			"item":            reasoningItem("completed"),
		})
		reasoningDone = true
	}

	emitMessageDone := func() {
		if !messageStarted || messageDone {
			return
		}
		idx := messageOutputIndex()
		seq++
		emitSSEEvent(w, flusher, "response.output_text.done", map[string]any{
			"type":            "response.output_text.done",
			"sequence_number": seq,
			"item_id":         msgID,
			"output_index":    idx,
			"content_index":   0,
			"text":            fullText,
			"logprobs":        []any{},
		})
		seq++
		emitSSEEvent(w, flusher, "response.content_part.done", map[string]any{
			"type":            "response.content_part.done",
			"sequence_number": seq,
			"item_id":         msgID,
			"output_index":    idx,
			"content_index":   0,
			"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": fullText},
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    idx,
			"item":            messageItem("completed"),
		})
		messageDone = true
	}

	emitToolCallDone := func(idx int, call map[string]any) {
		if done, _ := call["done"].(bool); done {
			return
		}
		call["done"] = true
		itemID, _ := call["item_id"].(string)
		callID, _ := call["call_id"].(string)
		name, _ := call["name"].(string)
		args, _ := call["arguments"].(string)
		seq++
		emitSSEEvent(w, flusher, "response.function_call_arguments.done", map[string]any{
			"type":            "response.function_call_arguments.done",
			"sequence_number": seq,
			"item_id":         itemID,
			"output_index":    idx,
			"arguments":       args,
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    idx,
			"item": map[string]any{
				"id":        itemID,
				"type":      "function_call",
				"status":    "completed",
				"arguments": args,
				"call_id":   callID,
				"name":      name,
			},
		})
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading stream: %v", err)
			return
		}
		if debugMode && strings.HasPrefix(line, "data: ") {
			log.Printf("[upstream raw chunk] %s", strings.TrimSpace(line[6:]))
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var chunk map[string]any
		if err := json.Unmarshal([]byte(line[6:]), &chunk); err != nil {
			continue
		}
		if !createdSent {
			if id, ok := chunk["id"].(string); ok && id != "" {
				responseID = id
				reasoningID = "rs_" + responseID + "_0"
				msgID = "msg_" + responseID + "_0"
			}
			if created, ok := chunk["created"].(float64); ok {
				createdAt = int64(created)
			}
			seq++
			emitSSEEvent(w, flusher, "response.created", map[string]any{
				"type":            "response.created",
				"sequence_number": seq,
				"response":        map[string]any{"id": responseID, "object": "response", "created_at": createdAt, "status": "in_progress", "background": false, "error": nil, "output": []any{}},
			})
			seq++
			emitSSEEvent(w, flusher, "response.in_progress", map[string]any{
				"type":            "response.in_progress",
				"sequence_number": seq,
				"response":        map[string]any{"id": responseID, "object": "response", "created_at": createdAt, "status": "in_progress"},
			})
			createdSent = true
		}
		choices, ok := chunk["choices"].([]any)
		if !ok || len(choices) == 0 {
			if usage, ok := chunk["usage"].(map[string]any); ok {
				totalUsage = usage
			}
			continue
		}

		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		finishReason, _ := choice["finish_reason"].(string)

		if rc, ok := delta["reasoning_content"]; ok && wantReasoning {
			rcStr, _ := rc.(string)
			if rcStr != "" {
				if !reasoningStarted {
					seq++
					emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
						"type":            "response.output_item.added",
						"sequence_number": seq,
						"output_index":    0,
						"item":            reasoningItem("in_progress"),
					})
					seq++
					emitSSEEvent(w, flusher, "response.reasoning_summary_part.added", map[string]any{
						"type":            "response.reasoning_summary_part.added",
						"sequence_number": seq,
						"item_id":         reasoningID,
						"output_index":    0,
						"summary_index":   0,
						"part":            map[string]any{"type": "summary_text", "text": ""},
					})
					reasoningStarted = true
				}
				fullReasoning += rcStr
				seq++
				emitSSEEvent(w, flusher, "response.reasoning_summary_text.delta", map[string]any{
					"type":            "response.reasoning_summary_text.delta",
					"sequence_number": seq,
					"item_id":         reasoningID,
					"output_index":    0,
					"summary_index":   0,
					"delta":           rcStr,
				})
			}
		}

		contentStr := ""
		if c, ok := delta["content"]; ok && c != nil {
			contentStr, _ = c.(string)
		}
		if contentStr != "" {
			emitReasoningDone()
			if !messageStarted {
				idx := messageOutputIndex()
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    idx,
					"item":            map[string]any{"id": msgID, "type": "message", "status": "in_progress", "content": []any{}, "role": "assistant"},
				})
				seq++
				emitSSEEvent(w, flusher, "response.content_part.added", map[string]any{
					"type":            "response.content_part.added",
					"sequence_number": seq,
					"item_id":         msgID,
					"output_index":    idx,
					"content_index":   0,
					"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": ""},
				})
				messageStarted = true
			}
			fullText += contentStr
			seq++
			emitSSEEvent(w, flusher, "response.output_text.delta", map[string]any{
				"type":            "response.output_text.delta",
				"sequence_number": seq,
				"item_id":         msgID,
				"output_index":    messageOutputIndex(),
				"content_index":   0,
				"delta":           contentStr,
				"logprobs":        []any{},
			})
		}

		rawToolCalls, _ := delta["tool_calls"].([]any)
		for _, rawToolCall := range rawToolCalls {
			tc, ok := rawToolCall.(map[string]any)
			if !ok {
				continue
			}
			idxFloat, _ := tc["index"].(float64)
			upstreamIndex := int(idxFloat)
			call, exists := toolCalls[upstreamIndex]
			if !exists {
				outputIndex := messageOutputIndex()
				if messageStarted {
					outputIndex++
				}
				outputIndex += len(toolOrder)
				callID, _ := tc["id"].(string)
				if callID == "" {
					callID = "call_" + randomString(12)
				}
				fn, _ := tc["function"].(map[string]any)
				name, _ := fn["name"].(string)
				call = map[string]any{
					"output_index": outputIndex,
					"item_id":      "fc_" + callID,
					"call_id":      callID,
					"name":         name,
					"arguments":    "",
					"done":         false,
				}
				toolCalls[upstreamIndex] = call
				toolOrder = append(toolOrder, upstreamIndex)
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    outputIndex,
					"item": map[string]any{
						"id":        call["item_id"],
						"type":      "function_call",
						"status":    "in_progress",
						"arguments": "",
						"call_id":   callID,
						"name":      name,
					},
				})
			}
			fn, _ := tc["function"].(map[string]any)
			if name, _ := fn["name"].(string); name != "" {
				call["name"] = name
			}
			if argDelta, _ := fn["arguments"].(string); argDelta != "" {
				call["arguments"] = call["arguments"].(string) + argDelta
				seq++
				emitSSEEvent(w, flusher, "response.function_call_arguments.delta", map[string]any{
					"type":            "response.function_call_arguments.delta",
					"sequence_number": seq,
					"item_id":         call["item_id"],
					"output_index":    call["output_index"],
					"delta":           argDelta,
				})
			}
		}

		if usage, ok := chunk["usage"].(map[string]any); ok {
			totalUsage = usage
		}
		if finishReason == "stop" || finishReason == "length" || finishReason == "content_filter" {
			emitReasoningDone()
			if !messageStarted && len(toolCalls) == 0 {
				idx := messageOutputIndex()
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    idx,
					"item":            map[string]any{"id": msgID, "type": "message", "status": "in_progress", "content": []any{}, "role": "assistant"},
				})
				seq++
				emitSSEEvent(w, flusher, "response.content_part.added", map[string]any{
					"type":            "response.content_part.added",
					"sequence_number": seq,
					"item_id":         msgID,
					"output_index":    idx,
					"content_index":   0,
					"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": ""},
				})
				messageStarted = true
			}
			emitMessageDone()
			for _, idx := range toolOrder {
				emitToolCallDone(toolCalls[idx]["output_index"].(int), toolCalls[idx])
			}
		}
	}

	emitReasoningDone()
	emitMessageDone()
	for _, idx := range toolOrder {
		emitToolCallDone(toolCalls[idx]["output_index"].(int), toolCalls[idx])
	}

	output := []any{}
	if reasoningStarted {
		output = append(output, reasoningItem("completed"))
	}
	if messageStarted {
		output = append(output, messageItem("completed"))
	}
	for _, idx := range toolOrder {
		call := toolCalls[idx]
		output = append(output, map[string]any{
			"id":        call["item_id"],
			"type":      "function_call",
			"status":    "completed",
			"arguments": call["arguments"],
			"call_id":   call["call_id"],
			"name":      call["name"],
		})
	}

	completedResponse := map[string]any{
		"id":                 responseID,
		"object":             "response",
		"created_at":         createdAt,
		"status":             "completed",
		"background":         false,
		"error":              nil,
		"incomplete_details": nil,
		"model":              model,
		"output":             output,
	}
	if len(tools) > 0 {
		completedResponse["tools"] = tools
	}
	if toolChoice != nil {
		completedResponse["tool_choice"] = toolChoice
	}

	if len(totalUsage) > 0 {
		usage := map[string]any{}
		if v, ok := totalUsage["prompt_tokens"]; ok {
			usage["input_tokens"] = v
		}
		if v, ok := totalUsage["prompt_tokens_details"]; ok {
			usage["input_tokens_details"] = v
		} else {
			usage["input_tokens_details"] = map[string]any{"cached_tokens": 0}
		}
		if v, ok := totalUsage["completion_tokens"]; ok {
			usage["output_tokens"] = v
		}
		if v, ok := totalUsage["completion_tokens_details"]; ok {
			usage["output_tokens_details"] = v
		}
		if v, ok := totalUsage["total_tokens"]; ok {
			usage["total_tokens"] = v
		}
		if v, ok := totalUsage["input_tokens"]; ok && usage["input_tokens"] == nil {
			usage["input_tokens"] = v
		}
		if v, ok := totalUsage["output_tokens"]; ok && usage["output_tokens"] == nil {
			usage["output_tokens"] = v
		}
		completedResponse["usage"] = usage
	}

	if totalUsage != nil {
		pt, _ := totalUsage["prompt_tokens"].(float64)
		ct, _ := totalUsage["completion_tokens"].(float64)
		tt, _ := totalUsage["total_tokens"].(float64)
		if tt > 0 {
			recordTokenUsage(model, int64(pt), int64(ct), int64(tt))
		}
	}

	seq++
	emitSSEEvent(w, flusher, "response.completed", map[string]any{
		"type":            "response.completed",
		"sequence_number": seq,
		"response":        completedResponse,
	})

	if flusher != nil {
		flusher.Flush()
	}
}

func convertChatToResponses(chatBody []byte, model string, wantReasoning bool, tools []Tool, toolChoice any) []byte {
	var chat struct {
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message struct {
				Content          string     `json:"content"`
				ReasoningContent string     `json:"reasoning_content"`
				ToolCalls        []ToolCall `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(chatBody, &chat); err != nil {
		log.Printf("Warning: convertChatToResponses unmarshal failed: %v", err)
	}

	text := ""
	reasoning := ""
	finishReason := ""
	var toolCalls []ToolCall
	if len(chat.Choices) > 0 {
		text = chat.Choices[0].Message.Content
		if wantReasoning {
			reasoning = chat.Choices[0].Message.ReasoningContent
		}
		toolCalls = chat.Choices[0].Message.ToolCalls
		finishReason = chat.Choices[0].FinishReason
	}

	status := "completed"
	if finishReason == "length" {
		status = "incomplete"
	}

	responses := map[string]any{
		"id":                 chat.ID,
		"object":             "response",
		"status":             status,
		"background":         false,
		"error":              nil,
		"incomplete_details": nil,
		"model":              model,
		"created_at":         chat.Created,
	}
	if len(tools) > 0 {
		responses["tools"] = tools
	}
	if toolChoice != nil {
		responses["tool_choice"] = toolChoice
	}
	outputID := "msg_" + chat.ID + "_0"
	output := []any{}
	if reasoning != "" {
		output = append(output, map[string]any{
			"id":                "rs_" + chat.ID,
			"type":              "reasoning",
			"encrypted_content": "",
			"summary":           []any{map[string]any{"type": "summary_text", "text": reasoning}},
		})
	}
	if text != "" {
		output = append(output, map[string]any{
			"id":     outputID,
			"type":   "message",
			"status": "completed",
			"role":   "assistant",
			"content": []any{map[string]any{
				"type":        "output_text",
				"text":        text,
				"annotations": []any{},
				"logprobs":    []any{},
			}},
		})
	}
	for _, tc := range toolCalls {
		output = append(output, map[string]any{
			"id":        "fc_" + tc.ID,
			"type":      "function_call",
			"status":    "completed",
			"arguments": tc.Function.Arguments,
			"call_id":   tc.ID,
			"name":      tc.Function.Name,
		})
	}
	responses["output"] = output
	if chat.Usage != nil {
		usage := map[string]any{}
		if v, ok := chat.Usage["prompt_tokens"]; ok {
			usage["input_tokens"] = v
		}
		if v, ok := chat.Usage["prompt_tokens_details"]; ok {
			usage["input_tokens_details"] = v
		} else {
			usage["input_tokens_details"] = map[string]any{"cached_tokens": 0}
		}
		if v, ok := chat.Usage["completion_tokens"]; ok {
			usage["output_tokens"] = v
		}
		if v, ok := chat.Usage["completion_tokens_details"]; ok {
			usage["output_tokens_details"] = v
		}
		if v, ok := chat.Usage["total_tokens"]; ok {
			usage["total_tokens"] = v
		}
		if v, ok := chat.Usage["input_tokens"]; ok && usage["input_tokens"] == nil {
			usage["input_tokens"] = v
		}
		if v, ok := chat.Usage["output_tokens"]; ok && usage["output_tokens"] == nil {
			usage["output_tokens"] = v
		}
		responses["usage"] = usage
	}

	result, _ := json.Marshal(responses)
	return result
}

func emitSSEEvent(w http.ResponseWriter, flusher http.Flusher, event string, data map[string]any) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling SSE event: %v", err)
		return
	}
	w.Write([]byte("event: " + event + "\n"))
	w.Write([]byte("data: " + string(jsonData) + "\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

// ======================== Admin 管理页面 ========================

// 用于日志中隐藏部分密钥
func maskKey(key string) string {
	if len(key) <= 4 {
		return "****"
	}
	return key[:2] + "****" + key[len(key)-2:]
}

func adminConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configMu.RLock()
		cfg := AppConfig{ModelAlias: modelAlias, ReasoningEffortMap: reasoningEffortMap, ForceDisableThinking: forceDisableThinking, APIKey: apiKey}
		configMu.RUnlock()
		socks5Mu.RLock()
		cfg.Socks5Proxies = socks5Proxies
		cfg.ActiveSocks5 = activeSocks5
		socks5Mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	case http.MethodPost:
		var cfg AppConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}
		if err := saveConfig(configPath, cfg); err != nil {
			http.Error(w, `{"error":"Failed to save config"}`, http.StatusInternalServerError)
			return
		}
		applyConfig(cfg)
		if debugMode {
			log.Printf("Config updated: aliases=%d, effort_map=%d, force_disable=%v, api_key=%s", len(cfg.ModelAlias), len(cfg.ReasoningEffortMap), cfg.ForceDisableThinking, maskKey(cfg.APIKey))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminStatsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tokenStatsMu.Lock()
		data, err := json.Marshal(tokenStats)
		tokenStatsMu.Unlock()
		if err != nil {
			http.Error(w, `{"error":"marshal error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	case http.MethodDelete:
		tokenStatsMu.Lock()
		tokenStats = &TokenStatsData{Models: map[string]*ModelStats{}}
		tokenStatsMu.Unlock()
		saveTokenStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminHTML))
}

const adminHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OC2API 管理面板</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f5f5;color:#333;line-height:1.6}
.container{max-width:900px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;font-weight:600;margin-bottom:4px}
.subtitle{color:#666;font-size:13px;margin-bottom:28px}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);padding:24px;margin-bottom:20px}
.card h2{font-size:15px;font-weight:600;margin-bottom:16px;color:#222}
.form-group{margin-bottom:14px}
.form-group:last-child{margin-bottom:0}
.form-group label{display:block;font-size:13px;font-weight:500;color:#555;margin-bottom:5px}
.form-group input,.form-group textarea{width:100%;padding:8px 12px;border:1px solid #d9d9d9;border-radius:6px;font-size:13px;font-family:monospace;transition:border-color .2s}
.form-group input:focus,.form-group textarea:focus{outline:none;border-color:#1677ff;box-shadow:0 0 0 2px rgba(22,119,255,.1)}
.form-group textarea{min-height:120px;resize:vertical}
.form-group .hint{font-size:11px;color:#999;margin-top:3px}
.actions{display:flex;gap:10px;margin-top:8px}
.btn{padding:8px 20px;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer;border:none;transition:all .2s}
.btn-primary{background:#1677ff;color:#fff}
.btn-primary:hover{background:#4096ff}
.btn-default{background:#f0f0f0;color:#333}
.btn-default:hover{background:#e0e0e0}
.btn-success{background:#52c41a;color:#fff}
.btn-success:hover{background:#73d13d}
.btn-warning{background:#fa8c16;color:#fff}
.btn-warning:hover{background:#ffa940}
.alias-table{width:100%;border-collapse:collapse;font-size:13px}
.alias-table th{text-align:left;font-weight:500;color:#555;padding:8px 12px;border-bottom:2px solid #f0f0f0;font-size:12px;letter-spacing:.5px}
.alias-table td{padding:8px 12px;border-bottom:1px solid #f5f5f5}
.alias-table input{width:100%;padding:6px 10px;border:1px solid #d9d9d9;border-radius:4px;font-size:13px;font-family:monospace}
.alias-table input:focus{outline:none;border-color:#1677ff}.m-select{width:100%;padding:6px 10px;border:1px solid #d9d9d9;border-radius:4px;font-size:13px;font-family:monospace;background:#fff}
.alias-table th:last-child{width:50px}
.alias-table td:last-child{white-space:nowrap;text-align:center}
.alias-table .btn{padding:4px 8px;font-size:12px;white-space:nowrap}
#toast{position:fixed;top:20px;right:20px;padding:10px 20px;border-radius:6px;font-size:13px;color:#fff;opacity:0;transition:opacity .3s;z-index:999}
#toast.success{background:#52c41a}
#toast.error{background:#ff4d4f}
#toast.show{opacity:1}
.empty-hint{color:#aaa;font-size:13px;padding:20px;text-align:center}
#loginOverlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:1000;align-items:center;justify-content:center}
#loginOverlay.show{display:flex}
.login-box{background:#fff;border-radius:10px;padding:32px;width:380px;max-width:90vw;box-shadow:0 8px 24px rgba(0,0,0,.15)}
.login-box h2{margin-bottom:6px}
.login-box p{color:#666;font-size:13px;margin-bottom:20px}
.login-box .form-group{margin-bottom:16px}
</style>
</head>
<body>
<div id="loginOverlay">
<div class="login-box">
<h2>OC2API 管理面板</h2>
<p>请输入 API Key 以登录管理后台</p>
<div class="form-group">
<input type="password" id="loginKey" placeholder="输入 API Key" autofocus onkeydown="if(event.key==='Enter')doLogin()">
<div class="error" id="loginError" style="color:#ff4d4f;font-size:12px;display:none;margin-top:8px">API Key 无效，请重试</div>
</div>
<button class="btn btn-primary" onclick="doLogin()" style="width:100%;text-align:center">登录</button>
</div>
</div>
<div class="container" id="mainContent" style="display:none">
<h1>OC2API 管理面板</h1>
<p class="subtitle">OpenCode 模型 -> OpenAI API 代理</p>

<div class="card">
<h2>Token 统计 <button class="btn btn-default" onclick="loadStats()" style="font-size:12px;padding:2px 10px;margin-left:8px;vertical-align:middle">刷新</button></h2>
<div id="statsContent" style="font-size:13px;margin-bottom:10px">
<div class="empty-hint">加载中...</div>
</div>
<div style="display:flex;gap:8px;align-items:center"><button class="btn btn-warning" onclick="resetStats()">清空统计</button><span id="resetStatus" style="font-size:12px;color:#999"></span></div>
</div>
<div class="card">
<h2>基本配置</h2>
<div class="form-group">
<label for="api_key">API Key（认证密钥）</label>
<input type="password" id="api_key" placeholder="留空则不启用 API Key 认证">
<div class="hint">客户端需在 Authorization 请求头中传入 <code>Bearer {api_key}</code>。留空 = 不启用认证。</div>
</div>
<div class="form-group">
<label>
<input type="checkbox" id="force_disable_thinking" style="margin-right:6px;width:auto">
<strong>强制禁用思考模式</strong>
</label>
<div class="hint">启用后，所有响应的推理内容将被移除</div>
</div>
<div class="actions">
<button class="btn btn-success" onclick="saveConfig()">保存配置</button>
<button class="btn btn-default" onclick="loadConfig()">重新加载</button>
</div>
</div>
<div class="card">
<h2>模型别名</h2>
<div style="margin-bottom:14px">
<table class="alias-table" id="aliasTable">
<thead><tr><th style="width:35%">别名（请求名）</th><th style="width:42%">实际模型（上游名）</th><th style="width:23%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="addAliasRow()">添加别名</button>
<button class="btn btn-success" onclick="saveConfig()">保存全部</button>
</div>
</div>
<div class="card">
<h2>推理力度映射</h2>
<div style="margin-bottom:14px">
<table class="alias-table" id="effortTable">
<thead><tr><th style="width:35%">请求值</th><th style="width:42%">映射值</th><th style="width:23%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="addEffortRow()">添加映射</button>
<button class="btn btn-success" onclick="saveConfig()">保存全部</button>
</div>
</div>
<div class="card">
<h2>SOCKS5 代理</h2>
<div style="margin-bottom:14px">
<table class="alias-table" id="socks5Table">
<thead><tr><th style="width:25%">名称</th><th style="width:30%">地址</th><th style="width:18%">用户名</th><th style="width:18%">密码</th><th style="width:9%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="form-group">
<label>启用代理</label>
<select id="activeSocks5" class="m-select">
<option value="">直连（不使用代理）</option>
</select>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="addSocks5Row()">添加代理</button>
<button class="btn btn-success" onclick="saveConfig()">保存全部</button>
</div>
</div>
</div>
<div id="toast"></div>
<script>
	let aliasData={},effortData={},modelList=[],socks5Data=[];
	async function apiFetch(url,opt){const h=opt&&opt.headers||{};const k=sessionStorage.getItem('oc2api_key');if(k)h['Authorization']='Bearer '+k;opt=opt||{};opt.headers=h;const r=await fetch(url,opt);if(r.status===401){sessionStorage.removeItem('oc2api_key');document.getElementById('loginOverlay').classList.add('show');document.getElementById('mainContent').style.display='none';throw new Error('Unauthorized')}return r}
	function doLogin(){const k=document.getElementById('loginKey').value.trim();if(!k){document.getElementById('loginError').style.display='block';return}sessionStorage.setItem('oc2api_key',k);document.getElementById('loginError').style.display='none';loadConfig()}
	async function loadConfig(){try{const r=await apiFetch('/admin/api/config');const cfg=await r.json();document.getElementById('api_key').value=cfg.api_key||'';document.getElementById('force_disable_thinking').checked=cfg.force_disable_thinking||false;aliasData=cfg.model_alias||{};effortData=cfg.reasoning_effort_map||{};socks5Data=cfg.socks5_proxies||[];const mr=await apiFetch('/v1/models');const md=await mr.json();modelList=(md.data||[]).map(m=>m.id);renderAliasTable();renderEffortTable();renderSocks5Table();document.getElementById('activeSocks5').value=cfg.active_socks5||'';document.getElementById('loginOverlay').classList.remove('show');document.getElementById('mainContent').style.display='block'}catch(e){showToast('认证失败: '+e.message,'error')}}
	function renderAliasTable(){const tb=document.querySelector('#aliasTable tbody');const ks=Object.keys(aliasData);if(!ks.length){tb.innerHTML='<tr><td colspan="3" class="empty-hint">暂无别名配置</td></tr>';return}tb.innerHTML=ks.map(k=>'<tr><td><input value="'+esc(k)+'" data-field="key"></td><td>'+modelSelectHtml(aliasData[k])+'</td><td><button class="btn btn-warning" onclick="delAlias(this)">删除</button></td></tr>').join('')}
	function modelSelectHtml(selected){let h='<select data-field="val" class="m-select">';h+='<option value="">-- 选择模型 --</option>';for(const m of modelList){h+='<option value="'+esc(m)+'"'+(selected===m?' selected':'')+'>'+esc(m)+'</option>'}h+='</select>';return h}
	function addAliasRow(){const tb=document.querySelector('#aliasTable tbody');if(tb.querySelector('.empty-hint'))tb.innerHTML='';tb.insertAdjacentHTML('beforeend','<tr><td><input value="" placeholder="例如: gpt-5.5" data-field="key"></td><td>'+modelSelectHtml('')+'</td><td><button class="btn btn-warning" onclick="delAlias(this)">删除</button></td></tr>')}
function delAlias(btn){const row=btn.closest('tr');const ki=row.querySelector('[data-field="key"]');if(ki&&ki.value&&aliasData[ki.value])delete aliasData[ki.value];row.remove();if(!Object.keys(aliasData).length)document.querySelector('#aliasTable tbody').innerHTML='<tr><td colspan="3" class="empty-hint">暂无别名配置</td></tr>'}
function collectAliases(){const r={};document.querySelectorAll('#aliasTable tbody tr').forEach(tr=>{const k=tr.querySelector('[data-field="key"]'),v=tr.querySelector('[data-field="val"]');if(k&&k.value.trim())r[k.value.trim()]=v?v.value.trim():''});aliasData=r;return r}
function renderEffortTable(){const tb=document.querySelector('#effortTable tbody');const ks=Object.keys(effortData);if(!ks.length){tb.innerHTML='<tr><td colspan="3" class="empty-hint">暂无映射配置</td></tr>';return}tb.innerHTML=ks.map(k=>'<tr><td><input value="'+esc(k)+'" data-field="key"></td><td><input value="'+esc(effortData[k])+'" data-field="val"></td><td><button class="btn btn-warning" onclick="delEffort(this)">删除</button></td></tr>').join('')}
function addEffortRow(){const tb=document.querySelector('#effortTable tbody');if(tb.querySelector('.empty-hint'))tb.innerHTML='';tb.insertAdjacentHTML('beforeend','<tr><td><input value="" placeholder="例如: low" data-field="key"></td><td><input value="" placeholder="例如: high" data-field="val"></td><td><button class="btn btn-warning" onclick="delEffort(this)">删除</button></td></tr>')}
function delEffort(btn){const row=btn.closest('tr');const ki=row.querySelector('[data-field="key"]');if(ki&&ki.value&&effortData[ki.value])delete effortData[ki.value];row.remove();if(!Object.keys(effortData).length)document.querySelector('#effortTable tbody').innerHTML='<tr><td colspan="3" class="empty-hint">暂无映射配置</td></tr>'}
function collectEfforts(){const r={};document.querySelectorAll('#effortTable tbody tr').forEach(tr=>{const k=tr.querySelector('[data-field="key"]'),v=tr.querySelector('[data-field="val"]');if(k&&k.value.trim())r[k.value.trim()]=v?v.value.trim():''});effortData=r;return r}
function renderSocks5Table(){const tb=document.querySelector('#socks5Table tbody');if(!socks5Data.length){tb.innerHTML='<tr><td colspan="5" class="empty-hint">暂无代理配置</td></tr>';return}tb.innerHTML=socks5Data.map((p,i)=>'<tr><td><input value="'+esc(p.name||'')+'" data-field="name"></td><td><input value="'+esc(p.addr)+'" data-field="addr" placeholder="例如: 127.0.0.1:1080"></td><td><input value="'+esc(p.username||'')+'" data-field="username"></td><td><input value="'+esc(p.password||'')+'" data-field="password" type="password"></td><td><button class="btn btn-warning" onclick="delSocks5('+i+')">删除</button></td></tr>').join('');renderSocks5Select()}
function addSocks5Row(){const tb=document.querySelector('#socks5Table tbody');if(tb.querySelector('.empty-hint'))tb.innerHTML='';socks5Data.push({addr:'',name:''});renderSocks5Table()}
function delSocks5(i){socks5Data.splice(i,1);renderSocks5Table()}
function collectSocks5(){const r=[];document.querySelectorAll('#socks5Table tbody tr').forEach(tr=>{const a=tr.querySelector('[data-field="addr"]');if(a&&a.value.trim())r.push({addr:a.value.trim(),name:(tr.querySelector('[data-field="name"]')||{}).value?.trim()||'',username:(tr.querySelector('[data-field="username"]')||{}).value?.trim()||'',password:(tr.querySelector('[data-field="password"]')||{}).value?.trim()||''})});socks5Data=r;return r}
function renderSocks5Select(){const sel=document.getElementById('activeSocks5');const cur=sel.value;sel.innerHTML='<option value="">直连（不使用代理）</option>';socks5Data.forEach(p=>{if(p.addr){const label=p.name?p.name+' ('+p.addr+')':p.addr;const opt=document.createElement('option');opt.value=p.addr;opt.textContent=label;sel.appendChild(opt)}});if(socks5Data.length>=2){const opt=document.createElement('option');opt.value='__round_robin__';opt.textContent='轮询（自动切换）';sel.appendChild(opt)}sel.value=cur;if(!sel.value)sel.value='';}
async function saveConfig(){collectAliases();collectEfforts();collectSocks5();const cfg={model_alias:aliasData,reasoning_effort_map:effortData,force_disable_thinking:document.getElementById('force_disable_thinking').checked,socks5_proxies:socks5Data,active_socks5:document.getElementById('activeSocks5').value,api_key:document.getElementById('api_key').value};try{const r=await apiFetch('/admin/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});if(!r.ok)throw new Error(await r.text());showToast('配置已保存','success');renderSocks5Select()}catch(e){showToast('保存失败: '+e.message,'error')}}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function showToast(msg,t){const e=document.getElementById('toast');e.textContent=msg;e.className=t+' show';clearTimeout(e._tid);e._tid=setTimeout(()=>e.classList.remove('show'),2500)}

async function resetStats(){if(!confirm('确认清空所有 Token 统计？\n此操作不可撤销。'))return;const s=document.getElementById('resetStatus');s.textContent='清空中...';try{const r=await apiFetch('/admin/api/stats',{method:'DELETE'});if(!r.ok)throw new Error(await r.text());document.getElementById('statsContent').innerHTML='<div class="empty-hint">暂无数据</div>';s.textContent='已清空';setTimeout(()=>s.textContent='',2000)}catch(e){s.textContent='失败: '+e.message}}
async function loadStats(){try{const r=await apiFetch('/admin/api/stats');const d=await r.json();const ms=d.models||{};const ks=Object.keys(ms);let h='<table class="alias-table"><thead><tr><th>模型</th><th>请求数</th><th>输入 Token</th><th>输出 Token</th><th>总计 Token</th></tr></thead><tbody>';if(!ks.length){h+='<tr><td colspan="5" class="empty-hint">暂无数据</td></tr>'}else{let tr=0,pt=0,ct=0,tt=0;for(const k of ks){const m=ms[k];h+='<tr><td>'+esc(k)+'</td><td>'+m.request_count+'</td><td>'+m.prompt_tokens+'</td><td>'+m.completion_tokens+'</td><td>'+m.total_tokens+'</td></tr>';tr+=m.request_count;pt+=m.prompt_tokens;ct+=m.completion_tokens;tt+=m.total_tokens}h+='<tr style="font-weight:600;background:#f8f8f8"><td>总计</td><td>'+tr+'</td><td>'+pt+'</td><td>'+ct+'</td><td>'+tt+'</td></tr>'}h+='</tbody></table>';document.getElementById('statsContent').innerHTML=h}catch(e){document.getElementById('statsContent').innerHTML='<div class="empty-hint">加载失败</div>'}}window.onload=async function(){try{const r=await fetch('/admin/api/config');if(r.ok){const cfg=await r.json();if(cfg.api_key){document.getElementById('loginOverlay').classList.add('show')}else{loadConfig();loadStats()}}else{document.getElementById('loginOverlay').classList.add('show')}}catch(e){document.getElementById('loginOverlay').classList.add('show')}};document.addEventListener('visibilitychange',function(){if(!document.hidden&&document.getElementById('mainContent').style.display!='none')loadStats()});
</script>
</body>
</html>`

// ======================== Main ========================

func main() {
	flag.StringVar(&port, "port", "8000", "服务端口")
	flag.StringVar(&configPath, "config", "config.json", "配置文件路径")
	flag.BoolVar(&debugMode, "debug", false, "启用调试日志")
	flag.Parse()

	cfg := loadConfig(configPath)
	if cfg.ReasoningEffortMap == nil {
		cfg.ReasoningEffortMap = map[string]string{"low": "high", "medium": "high", "xhigh": "max"}
	}
	applyConfig(cfg)
	if err := saveConfig(configPath, cfg); err != nil {
		log.Printf("警告: 无法保存配置: %v", err)
	}

	loadTokenStats()
	log.Printf("配置已从 %s 加载", configPath)
	initOCSession()
	models, err := fetchModels()
	if err != nil {
		log.Printf("警告: 无法获取模型列表: %v", err)
	} else {
		modelMu.Lock()
		modelsCache = models
		modelsLoaded = true
		modelMu.Unlock()
		log.Printf("已加载 %d 个模型:", len(models))
		for _, m := range models {
			log.Printf("  - %s", m.ID)
		}
	}
	log.Printf("OC2API 代理服务器")
	log.Printf("===================")
	log.Printf("端口:     %s", port)
	log.Printf("上游:     https://opencode.ai/zen/v1/chat/completions (API)")
	log.Printf("模型：  %d 个模型已加载", len(getModelIDs()))
	log.Printf("别名：  %d", len(modelAlias))
	log.Printf("管理:    http://localhost:%s/admin", port)
	log.Printf("===================")
	http.HandleFunc("/v1/chat/completions", authMiddleware(chatCompletionsHandler))
	http.HandleFunc("/v1/responses", authMiddleware(responsesHandler))
	http.HandleFunc("/v1/messages", authMiddleware(claudeMessagesHandler))
	http.HandleFunc("/v1/models", authMiddleware(listModelsHandler))
	http.HandleFunc("/admin", authMiddleware(adminPageHandler))
	http.HandleFunc("/admin/api/config", authMiddleware(adminConfigHandler))
	http.HandleFunc("/admin/api/stats", authMiddleware(adminStatsHandler))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	addr := ":" + port
	log.Printf("服务器启动在 %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}








