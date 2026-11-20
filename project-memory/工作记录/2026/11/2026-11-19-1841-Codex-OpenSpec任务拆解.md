---
type: worklog
project: KeyKoi
workstream: openspec-planning
status: completed
recorded_at: 2026-11-19T18:41:47+08:00
started_at: unknown
completed_at: 2026-11-19T18:41:47+08:00
timezone: Asia/Shanghai
agent: Codex
client: Codex Desktop
model: GPT-6
session_id: unavailable
branch: unavailable
commit: null
---

# 按 v0.1 草案编写 OpenSpec

## 任务计划书

[[project-memory/任务计划/OpenSpec任务拆解]]，完成阶段拆解、产物写入和验证。

## 目标与结果

将 v0.1 转为 15 个可分别执行的变更。路线图列出各阶段依赖、起始任务和验收结果。此记录对应文档交付，各开发任务均待执行。

## 参考文档

- [[KeyKoi_Implementation_Plan_v0.1|实施设计草案]] 提供能力范围、技术选型、验收和阶段顺序。

## 文档产物

- 新建 [[openspec/roadmap|实施路线图]]、[[project-memory/任务计划/OpenSpec任务拆解|规划任务计划]] 和 [[project-memory/工作流/OpenSpec任务拆解|规划工作流]]。
- 更新 [[project-memory/首页|项目记忆首页]]、[[project-memory/环境与部署|环境与部署]]、[[docs/首页|文档首页]] 和 [[docs/索引/计划与决策|计划索引]]。
- 新建各变更的提案、设计、规格和任务清单。
- p0-broker-gateway-helper：[[openspec/changes/p0-broker-gateway-helper/proposal|提案]]、[[openspec/changes/p0-broker-gateway-helper/design|设计]]、[[openspec/changes/p0-broker-gateway-helper/specs/broker-gateway-helper-prototype/spec|规格]]、[[openspec/changes/p0-broker-gateway-helper/tasks|任务]]。
- p0-linux-file-prototype：[[openspec/changes/p0-linux-file-prototype/proposal|提案]]、[[openspec/changes/p0-linux-file-prototype/design|设计]]、[[openspec/changes/p0-linux-file-prototype/specs/linux-file-isolation-prototype/spec|规格]]、[[openspec/changes/p0-linux-file-prototype/tasks|任务]]。
- p1-encrypted-vault：[[openspec/changes/p1-encrypted-vault/proposal|提案]]、[[openspec/changes/p1-encrypted-vault/design|设计]]、[[openspec/changes/p1-encrypted-vault/specs/encrypted-vault/spec|规格]]、[[openspec/changes/p1-encrypted-vault/tasks|任务]]。
- p1-http-gateway：[[openspec/changes/p1-http-gateway/proposal|提案]]、[[openspec/changes/p1-http-gateway/design|设计]]、[[openspec/changes/p1-http-gateway/specs/explicit-http-gateway/spec|规格]]、[[openspec/changes/p1-http-gateway/tasks|任务]]。
- p1-local-session-broker：[[openspec/changes/p1-local-session-broker/proposal|提案]]、[[openspec/changes/p1-local-session-broker/design|设计]]、[[openspec/changes/p1-local-session-broker/specs/local-session-broker/spec|规格]]、[[openspec/changes/p1-local-session-broker/tasks|任务]]。
- p1-management-release：[[openspec/changes/p1-management-release/proposal|提案]]、[[openspec/changes/p1-management-release/design|设计]]、[[openspec/changes/p1-management-release/specs/standalone-management-release/spec|规格]]、[[openspec/changes/p1-management-release/tasks|任务]]。
- p1-runtime-delivery：[[openspec/changes/p1-runtime-delivery/proposal|提案]]、[[openspec/changes/p1-runtime-delivery/design|设计]]、[[openspec/changes/p1-runtime-delivery/specs/native-runtime-delivery/spec|规格]]、[[openspec/changes/p1-runtime-delivery/tasks|任务]]。
- p1-tool-integration：[[openspec/changes/p1-tool-integration/proposal|提案]]、[[openspec/changes/p1-tool-integration/design|设计]]、[[openspec/changes/p1-tool-integration/specs/managed-tool-integration/spec|规格]]、[[openspec/changes/p1-tool-integration/tasks|任务]]。
- p2-linux-controlled-runtime：[[openspec/changes/p2-linux-controlled-runtime/proposal|提案]]、[[openspec/changes/p2-linux-controlled-runtime/design|设计]]、[[openspec/changes/p2-linux-controlled-runtime/specs/linux-controlled-file-runtime/spec|规格]]、[[openspec/changes/p2-linux-controlled-runtime/tasks|任务]]。
- p3-central-device-broker：[[openspec/changes/p3-central-device-broker/proposal|提案]]、[[openspec/changes/p3-central-device-broker/design|设计]]、[[openspec/changes/p3-central-device-broker/specs/central-device-broker/spec|规格]]、[[openspec/changes/p3-central-device-broker/tasks|任务]]。
- p4-database-proxy：[[openspec/changes/p4-database-proxy/proposal|提案]]、[[openspec/changes/p4-database-proxy/design|设计]]、[[openspec/changes/p4-database-proxy/specs/database-protocol-proxy/spec|规格]]、[[openspec/changes/p4-database-proxy/tasks|任务]]。
- p4-oauth-refresh：[[openspec/changes/p4-oauth-refresh/proposal|提案]]、[[openspec/changes/p4-oauth-refresh/design|设计]]、[[openspec/changes/p4-oauth-refresh/specs/managed-oauth-refresh/spec|规格]]、[[openspec/changes/p4-oauth-refresh/tasks|任务]]。
- p4-protocol-signer：[[openspec/changes/p4-protocol-signer/proposal|提案]]、[[openspec/changes/p4-protocol-signer/design|设计]]、[[openspec/changes/p4-protocol-signer/specs/registered-protocol-signer/spec|规格]]、[[openspec/changes/p4-protocol-signer/tasks|任务]]。
- p4-ssh-agent：[[openspec/changes/p4-ssh-agent/proposal|提案]]、[[openspec/changes/p4-ssh-agent/design|设计]]、[[openspec/changes/p4-ssh-agent/specs/managed-ssh-agent/spec|规格]]、[[openspec/changes/p4-ssh-agent/tasks|任务]]。
- p4-trusted-tls-proxy：[[openspec/changes/p4-trusted-tls-proxy/proposal|提案]]、[[openspec/changes/p4-trusted-tls-proxy/design|设计]]、[[openspec/changes/p4-trusted-tls-proxy/specs/tool-trusted-https-proxy/spec|规格]]、[[openspec/changes/p4-trusted-tls-proxy/tasks|任务]]。

## 配置

- 初始化 `openspec/config.yaml` 的 spec-driven 工作流和每项变更的元数据。

## 验证与下一步

- `openspec validate --changes --strict --no-interactive` 验证 15 项通过。核对 26 项需求、29 个场景、62 项待执行任务及前置关系；P0 主线的四类产物齐备。
- 开发先执行 [[openspec/changes/p0-broker-gateway-helper/tasks|P0 主线任务 1.1]]。P0 Linux 可并行；后续目标工具、平台能力与性能仍按任务实测确认。
