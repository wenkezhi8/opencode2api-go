# opencode2api-go

OpenCode 转 OpenAI 兼容 API 的 Go 代理。

## 编译

```bash
go build -ldflags="-s -w" -o opencode2api main.go
```

编译后生成单个静态二进制文件 `opencode2api`，无任何外部依赖。

## 部署

### 1. 放置文件

```bash
mkdir -p /opt/opencode2api-go
cp opencode2api /opt/opencode2api-go/
cp config.json /opt/opencode2api-go/
```

### 2. 编辑配置

编辑 `config.json`，根据上游服务配置模型别名和代理：

```json
{
  "model_alias": {
    "gpt-4o": "gpt-4o-upstream"
  },
  "model_whitelist": ["gpt-4o-upstream"],
  "reasoning_effort_map": {
    "low": "high",
    "medium": "high",
    "xhigh": "max"
  },
  "force_disable_thinking": false
}
```

### 3. 配置 systemd 服务

```bash
cat > /etc/systemd/system/opencode2api.service << 'EOF'
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
EOF

systemctl daemon-reload
systemctl enable --now opencode2api
```

### 4. 验证

```bash
curl http://localhost:10000/health
# 预期输出: OK

curl http://localhost:10000/v1/models
# 返回模型列表
```

## 配置说明

| 参数 | 说明 |
|------|------|
| `--port` | 监听端口（默认 8000） |
| `--config` | 配置文件路径（默认 config.json） |
| `--debug` | 启用调试日志 |

## 管理页面

启动后访问 `http://localhost:10000/admin` 可查看：

- 在线编辑模型别名和代理
- Token 使用统计
- 模型列表

## 许可证

MIT
