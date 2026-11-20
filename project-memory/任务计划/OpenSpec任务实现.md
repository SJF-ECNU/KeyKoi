---
type: task-plan
project: KeyKoi
workstream: openspec-implementation
status: active
updated_at: 2026-11-19
---

# OpenSpec 任务逐一实现

## 目标、范围与方案

把已写好的 15 个 OpenSpec 变更按路线图依赖逐一实现，并在当前 Mac 原生 macOS 上按各变更 `tasks.md` 的验收口径取证。

- 依据：[[openspec/roadmap|实施路线图]]、[[KeyKoi_Implementation_Plan_v0.1|v0.1 实施设计草案]]、各变更的 proposal / design / spec。
- 交付物：Go 应用（`cmd/`、`internal/`、`adapters/`、`web/`）、测试与受控上游、验收记录、更新后的 tasks 勾选。
- 范围：P0 主线 → P1 六项 → P3 → P4 五项；Linux 专项（`p0-linux-file-prototype`、`p2-linux-controlled-runtime`）按路线图延期，不实现。
- 完成条件：每条任务有对应实现或验收证据；不能验证的条目保持未勾选并写明原因。

执行清单直接使用各变更的 `tasks.md`，本计划不复制步骤表：

- P0：[[openspec/changes/p0-broker-gateway-helper/tasks|p0-broker-gateway-helper]]
- P1：[[openspec/changes/p1-encrypted-vault/tasks|p1-encrypted-vault]]、[[openspec/changes/p1-local-session-broker/tasks|p1-local-session-broker]]、[[openspec/changes/p1-http-gateway/tasks|p1-http-gateway]]、[[openspec/changes/p1-runtime-delivery/tasks|p1-runtime-delivery]]、[[openspec/changes/p1-tool-integration/tasks|p1-tool-integration]]、[[openspec/changes/p1-management-release/tasks|p1-management-release]]
- P3：[[openspec/changes/p3-central-device-broker/tasks|p3-central-device-broker]]
- P4：[[openspec/changes/p4-ssh-agent/tasks|p4-ssh-agent]]、[[openspec/changes/p4-protocol-signer/tasks|p4-protocol-signer]]、[[openspec/changes/p4-oauth-refresh/tasks|p4-oauth-refresh]]、[[openspec/changes/p4-database-proxy/tasks|p4-database-proxy]]、[[openspec/changes/p4-trusted-tls-proxy/tasks|p4-trusted-tls-proxy]]

## 总体方案

1. 单一 Go 模块，共享 `internal/model`（四个核心对象、交付模式、错误码）、`internal/secret`（秘密封装）与 `internal/store`（内存 / SQLite / PostgreSQL）。
2. P0 用内存实现验证授权、注入、流式与真实 Helper 通道；测量证据写入验收记录。
3. P1 在同一接口上换成 SQLite 加密密钥库与受认证本机 IPC；网关、运行器、适配器、管理入口复用同一 Resolver 与许可校验。
4. P3 增加 PostgreSQL 中心与设备许可；P4 在 Broker 之上增加 SSH Agent、SigV4 签名、OAuth 刷新、数据库协议代理与受信 TLS 代理。
5. 所有测试使用运行时生成的凭证和本机受控上游，不写入真实业务密钥。

## 执行步骤与证据

| 步骤 | 动作 | 验证 | 状态 |
| --- | --- | --- | --- |
| 1 | 脚手架与核心对象 | `go test ./internal/model ./internal/secret` | completed |
| 2 | P0 原型与测量 | P0 tasks 2.1–2.3 证据 | completed |
| 3 | P1 密钥库 | P1 vault tasks 2.1–2.2 | completed |
| 4 | P1 会话与 Broker | session tasks 2.1–2.2 | completed |
| 5 | P1 网关 | gateway tasks 2.1–2.2 | completed |
| 6 | P1 运行时交付 | runtime tasks 2.1–2.2 | completed |
| 7 | P1 工具接入 | integration tasks 2.1–2.2 | completed |
| 8 | P1 管理发布 | management tasks 2.1–2.2 | completed |
| 9 | P3 中心 | P3 tasks 2.1–2.2（2.1 的休眠与时间偏差未单独注入） | completed |
| 10 | P4 五项协议 | 各 P4 tasks 2.1 | completed |
| 11 | 文档与记忆收尾 | 验收记录、tasks 勾选、工作记录 | completed |

## 扩展工作（OpenSpec 之外）

用户决定模型 API Key 不是重点（可用中转站解决），优先补其他认证形态：

| 扩展项 | 范围 | 状态 |
| --- | --- | --- |
| OAuth2 client_credentials / JWT bearer | 网关按需换 token 并注入 Bearer，缓存与 single-flight | active |
| 腾讯云 TC3 / 华为云 AK-SK 签名 | `/v1/signatures` 新协议 + CLI | active |
| Redis / MySQL / MongoDB 认证代理 | 客户端用会话令牌代替真实密码 | active |

## 当前进度、下一步与未决项

- 已完成 13 个变更的实现与本机验收，证据见 [[docs/验收/验收总览|验收总览]]；Linux 两项按路线图未实现。
- 额外验证：aliyun-cli 3.5.3 经 `keykoi run` 运行时交付完成真实签名请求（`tests/acceptance/tool-aliyun.sh`，12/12）。
- 额外能力：PATH shim 无感入口（`internal/shim`、`keykoi shim`），验收 `shim-aliyun.sh` 19/19。
- 下一步候选：补 P3 休眠/时间偏差场景；把 TLS 代理纳入 daemon 的会话与锁定通道；为数据库与签名补正式 Binding 字段（当前用 HTTP origin 与 `adapter_id` 约定占位）。
- 未决项：跨物理主机拓扑、Windows 验收、中心托管 CA、非 S3 签名与预签名按范围限制。
