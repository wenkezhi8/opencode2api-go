# opencode2api-go

OpenCode 转 OpenAI 兼容 API 的 Go 代理。

## 编译

```bash
go build -ldflags="-s -w" -o opencode2api main.go
```

## 运行

```bash
./opencode2api --port 10000 --config config.json
```

## systemd 服务

```ini
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
```
