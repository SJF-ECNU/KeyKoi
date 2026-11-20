# 使用看板与按主体授权

## Why

管理页目前用原始 JSON 显示审计和授权，授权时还需查找内部主体 ID。

## What Changes

- 用可筛选的使用记录表替换审计 JSON。
- 提供当前 macOS 账户、Codex App、Codex CLI 和 Claude Code 内置授权目标，管理页可创建和撤销授权。
- 守护进程依据本机连接进程识别代理；现有账户级授权继续生效。

## Capabilities

### New Capabilities

- `local-activity-and-subject-grants`

## Impact

涉及本机 IPC 身份归属、Broker、管理 Web UI 和 CLI。沿用现有凭证、Binding、交付模式、许可期限及管理员边界。

通用 Agent 可经管理 API、看板或 CLI 登记原生可执行文件。
