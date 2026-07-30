# opencode2api-go

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)

**opencode2api-go** 是一个轻量级 API 代理，将 [OpenCode](https://opencode.ai) 的 API 转换为标准的 **OpenAI 兼容 API** 格式。单文件 Go 实现，零外部依赖，开箱即用。

> 如果你在使用任何兼容 OpenAI API 的客户端（如 ChatGPT Next Web、LobeChat、Open WebUI、Cursor、VS Code Copilot 等），可以将其 API 端点指向本代理，即可接入 OpenCode 模型。

---

## 功能特性

- **API 转换**
  - OpenAI `POST /v1/chat/completions`（流式 + 非流式）
  - OpenAI `POST /v1/responses`（流式 + 非流式）
  - Claude `POST /v1/messages`（流式 + 非流式）
  - OpenAI `GET /v1/models`

- **模型别名** — 自定义模型名与上游模型映射，白名单控制可用模型

- **SOCKS5 代理** — 支持多个 SOCKS5 代理、轮询策略，适用于需要代理访问的场景

- **推理配置**
  - `reasoning_effort` 映射（low → high, medium → high, xhigh → max）
  - 可禁用 thinking 输出

- **Token 统计** — 按模型统计请求数、输入/输出/总 Token 数

- **管理后台** — 内置 Web 管理页面，实时编辑配置和查看统计

- **健康检查** — `GET /health` 返回 `OK`

---

## 快速开始

### 编译

```bash
git clone https://github.com/wenkezhi8/opencode2api-go.git
cd opencode2api-go
go build -ldflags="-s -w" -o opencode2api main.go
```

编译后生成单个静态二进制文件 `opencode2api`，仅 8-9 MB，无任何外部依赖（无需 Node.js、Python 等运行时）。

### 配置

编辑 `config.json`:

```json
{
  "model_alias": {
    "gpt-4o": "gpt-4o-upstream",
    "deepseek-v4": "deepseek-v4-flash-free"
  },
  "reasoning_effort_map": {
    "low": "high",
    "medium": "high",
    "xhigh": "max"
  },
  "force_disable_thinking": false,
  "model_whitelist": ["gpt-4o-upstream", "deepseek-v4-flash-free"]
}
```

| 配置项 | 说明 |
|--------|------|
| `model_alias` | 模型别名映射，客户端请求的模型名 → 上游实际模型名 |
| `reasoning_effort_map` | 推理努力程度映射 |
| `force_disable_thinking` | 是否强制禁用 thinking 输出（流式响应中去除 reasoning 部分） |
| `model_whitelist` | 允许使用的模型列表，留空则允许所有 |
| `socks5_proxies` | SOCKS5 代理配置数组（可选） |
| `active_socks5` | 当前激活的代理名，设为 `"__round_robin__"` 可轮询所有代理 |

关于 `config.json` 的完整配置也会在首次启动后自动生成并补全。

### 运行

```bash
./opencode2api --port 10000 --config config.json
```

启动后日志示例：

```
配置已从 config.json 加载
已加载 30 个模型
OC2API 代理服务器
端口:     10000
上游:     https://opencode.ai/zen/v1/chat/completions (API)
模型：   30 个模型已加载
管理:    http://localhost:10000/admin
服务器启动在 :10000
```

### 验证

```bash
# 健康检查
curl http://localhost:10000/health
# → OK

# 获取可用模型列表
curl http://localhost:10000/v1/models
# → {"data":[{"id":"model-xxx",...}],"object":"list"}

# OpenAI Chat Completions
curl http://localhost:10000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}'
```

---

## 部署

### systemd 服务（推荐）

```bash
# 放置文件
mkdir -p /opt/opencode2api-go
cp opencode2api config.json /opt/opencode2api-go/

# 注册服务
cat > /etc/systemd/system/opencode2api.service << 'SERVICEEOF'
[Unit]
Description=OC2API - OpenCode to OpenAI Proxy (Go)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/opencode2api-go
ExecStart=/opt/opencode2api-go/opencode2api --port 10000 --config config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable --now opencode2api

# 查看日志
journalctl -u opencode2api -f
```

### Docker（可选）

项目不带 Dockerfile，但可以直接在容器内运行二进制：

```bash
docker run -d --restart always \
  -v /opt/opencode2api-go:/app \
  -p 10000:10000 \
  --name opencode2api \
  alpine:latest /app/opencode2api --port 10000 --config /app/config.json
```

### Nginx 反向代理

```nginx
server {
    listen 443 ssl;
    server_name api.your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 300s;
    }
}
```

---

## 架构

```
┌─────────────────────────────────────────────────┐
│              客户端应用                           │
│  (ChatGPT Next Web, Cursor, LobeChat, 自定义等)  │
└──────────────────┬──────────────────────────────┘
                   │ OpenAI / Claude 兼容 API
                   ▼
┌─────────────────────────────────────────────────┐
│          opencode2api-go (代理服务)              │
│                                                  │
│  ┌──────────┐  ┌───────────┐  ┌──────────────┐  │
│  │ API 转换  │  │模型别名映射│  │ SOCKS5 代理  │  │
│  ├──────────┤  ├───────────┤  ├──────────────┤  │
│  │流式/非流式│  │ 白名单控制 │  │ 轮询/指定代理│  │
│  │Token 统计│  │推理配置   │  │              │  │
│  └──────────┘  └───────────┘  └──────────────┘  │
│                                                  │
└──────────────────┬──────────────────────────────┘
                   │ OpenCode API
                   ▼
┌─────────────────────────────────────────────────┐
│          OpenCode AI (opencode.ai)              │
└─────────────────────────────────────────────────┘
```

### 支持的 API 端点

| 端点 | 客户端请求 | 说明 |
|------|-----------|------|
| `/v1/chat/completions` | OpenAI 格式 | **推荐**，功能最完整，支持流式、thinking、工具调用 |
| `/v1/responses` | OpenAI Responses API | 支持工具调用、函数输出收集 |
| `/v1/messages` | Claude 格式 | Anhtropic Messages API 转换为 OpenAI |
| `/v1/models` | OpenAI 格式 | 获取可用的模型列表 |
| `/admin` | 浏览器 | 管理后台 |
| `/health` | GET | 健康检查 |

### SOCKS5 代理

支持在 config.json 中配置多个 SOCKS5 代理，可用于绕过网络限制访问 OpenCode API：

```json
{
  "socks5_proxies": [
    {"addr": "127.0.0.1:1080", "name": "local"},
    {"addr": "proxy.example.com:1080", "username": "user", "password": "pass", "name": "remote"}
  ],
  "active_socks5": "local"
}
```

- `active_socks5`: 设为代理名使用指定代理
- `active_socks5`: 设为 `"__round_robin__"` 轮询所有代理
- `active_socks5`: 设为空字符串表示直连（不使用代理）

### 流式响应

代理完整支持 Server-Sent Events (SSE) 流式响应，客户端设置 `stream: true` 即可使用：

- OpenAI Chat Completions 流式格式
- OpenAI Responses API 流式格式（`stream: true` + `stream_options: {"include_usage": true}`）
- Claude Messages 流式格式

---

## 管理后台

启动后访问 `http://localhost:10000/admin`：

- **模型列表** — 查看从 OpenCode 获取的所有可用模型
- **模型别名** — 在线编辑模型别名映射
- **SOCKS5 代理** — 配置代理并切换当前使用的代理
- **推理配置** — 调整 reasoning_effort 映射和 thinking 开关
- **Token 统计** — 按模型查看请求数和 Token 消耗（支持清空统计）

![管理后台截图](docs/admin-panel.png)

> 管理后台不设密码认证（仅监听本地端口）。如果对外暴露，请通过 Nginx 添加认证。

---

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--port` | `8000` | 服务监听端口 |
| `--config` | `config.json` | 配置文件路径 |
| `--debug` | `false` | 启用调试日志 |

---

## 开发

项目只有一个源文件 `main.go`，使用 Go 标准库实现，无第三方依赖。

```bash
# 编译
go build -o opencode2api main.go

# 运行开发模式（端口 8080）
go run main.go --port 8080 --config dev.config.json --debug
```

---

## 对比原版 (Node.js)

| 特性 | opencode2api-go | opencode2api (Node.js) |
|------|----------------|----------------------|
| 运行时 | 单二进制，无依赖 | 需要 Node.js 运行时 |
| 体积 | 8-9 MB | 依赖 > 200 MB (含 node_modules) |
| 性能 | 原生编译，高吞吐 | 解释执行 |
| 部署 | 复制二进制即可 | 需安装 npm 依赖 |
| API 转换 | OpenAI + Claude + Responses | 仅 OpenAI |
| 代理支持 | SOCKS5 多代理 + 轮询 | 无 |
| 管理页面 | 有 | 无 |
| Token 统计 | 有 | 无 |

---

## 许可证

[MIT](LICENSE)
