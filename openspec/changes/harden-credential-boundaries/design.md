## Context

[[docs/验收/2026-11-20-全量测试]] 提供上一轮结果。对应 [[project-memory/工作流/本机凭证边界加固]]。

## Goals / Non-Goals

保留现有主体识别和 IPC 客户端。收紧 IPC 对象归属，默认保护 MongoDB 上游链路，使用仍受支持的工具链。代理下游继续沿用仅本机的 PLAIN 会话令牌入口。

## Decisions

- 管理员复用现有证明。普通 IPC 请求使用和创建会话一致的 Unix peer 主体，归属校验在 Broker 的对象修改锁内完成。完整审计仅管理员可读。
- MongoDB 上游默认使用 TLS 并验证证书链和登记的主机名。沿用 `--upstream-ca`，允许用 `--upstream-insecure` 连接明确的明文上游。原有 HTTPS 地址始终使用 TLS。TLS 失败直接结束连接。
- Go 和 x/crypto 从官方渠道更新，使用修补后的 Go 重建并复扫。

## Risks / Trade-offs

- 本机 OS 用户仍是文件与进程权限边界，同 UID 的进程可依系统权限访问管理令牌。
- 原本依赖明文的 MongoDB 必须用显式选项启动代理，或为数据库启用 TLS。
- Go 最低版本上调后，锁定旧工具链的环境需要先更新。

执行清单见 [tasks.md](tasks.md)。
