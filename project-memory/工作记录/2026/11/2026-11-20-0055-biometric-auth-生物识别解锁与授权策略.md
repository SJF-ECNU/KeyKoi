---
type: worklog
project: KeyKoi
workstream: biometric-unlock-and-auth-policy
status: completed
recorded_at: 2026-11-20T00:55:00+08:00
started_at: unknown
completed_at: 2026-11-20T00:55:00+08:00
timezone: Asia/Shanghai
agent: biometric-auth
client: DeepSeek Harness
model: deepseek-v4
session_id: unavailable
branch: unavailable
commit: null
---

# 实现 Touch ID 解锁与授权策略

## 任务计划书

[[project-memory/任务计划/生物识别解锁与授权策略|任务计划书 · 生物识别解锁与授权策略]]，本次完成全部步骤。

## 结果、改动与验证

根密钥仍是随机 32 字节，由新 Swift 助手写入 macOS Keychain（ACL `biometryCurrentSet`），Touch ID 通过后交给 keykoid；`vault.UnlockWithRootKey` 先用已有密文校验根密钥再解锁，错误密钥返回 `VAULT_UNLOCK_FAILED`。`Init` 后自动登记，失败只记录状态。

Grant 增加 `auth_requirement`（`once` 默认 / `window:<秒>` / `per_use` / `permanent`）。SQLite 通过 `ALTER TABLE` 迁移旧库并给旧行安全默认值；Memory store 同步。Broker 在放行前调用 `Authenticator.Require`，验证状态只存内存 `AuthCache`（principal+grant+mode → method/verified_at/expires_at，once 绑定会话、window 按秒过期、per_use 不缓存、permanent 不验证），锁库、会话撤销、授权撤销、凭证轮换、服务重启都会清空。

失败语义：用户取消或验证失败 `AUTH_REQUIRED`（HTTP 401），无生物识别/非 GUI/未登记 `AUTH_UNAVAILABLE`（HTTP 503）。无生物识别时回退一次性主密码证明（`POST /v1/auth/verify` 或 `keykoi auth verify --method password`），一次证明只放行一次用钥；回退也不可用时 CLI 与 UI 都能明确失败，不静默放行。审计每条 allowed/denied 都带 `auth_method` 与 `auth_result`。

验证：`bash tests/acceptance/biometric-auth.sh` 65/65（四种策略语义、锁定/撤销/轮换清空、助手不可用回退与拒绝、审计字段、管理 HTTP 状态码、UI 控件）；`go test ./internal/{vault,broker,store,daemon}`、`go build ./...`、`go test ./...` 全部通过。真机 `packaging/macos/keykoi-biometric available` 返回 0；`store` 因助手中缺少 `keychain-access-groups` 权限返回 -34018（errSecMissingEntitlement），已在助手内给出签名提示并把真实 `store/load` 标为 manual。

## 参考文档

- [[KeyKoi_Implementation_Plan_v0.1|实施设计草案]] 的密钥库、Session、Grant 与审计边界。
- [[docs/验收/验收总览|验收总览]] 的验收惯例与证据目录约定。

## 文档产物

- 新建 `packaging/macos/keykoi-biometric.swift`、`packaging/macos/build-biometric.sh`、`packaging/macos/keykoi-biometric.entitlements`。
- 更新 `packaging/macos/install.sh`（可选安装 Touch ID 助手）。
- 新建 `tests/fixtures/biometricstub/main.go`、`tests/acceptance/biometric-auth.sh`、`docs/验收/artifacts/biometric-auth/result.json`。
- 更新 [[docs/验收/验收总览|验收总览]]：新增结果行、Touch ID 章节与复测命令。
- 新建 [[project-memory/任务计划/生物识别解锁与授权策略|任务计划书]] 与 [[project-memory/工作流/生物识别解锁与授权策略|工作流]]，并更新 [[project-memory/首页|项目记忆首页]] 的工作流列表。

## 剩余工作与下一步

真实 Keychain 的 `store/load` 需要在带 `keychain-access-groups` 权限的签名助手上手工确认一次 Touch ID，随后可把该步纳入自动验收；在此之前主密码始终是唯一恢复入口。
