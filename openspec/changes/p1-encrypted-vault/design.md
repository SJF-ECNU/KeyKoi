# P1 · 单机加密密钥库设计

## Context

单机版需要让指定数据库提供唯一权威的凭证组合版本，并让锁定、轮换、备份恢复具有可验证语义。

## Goals / Non-Goals

实现 SQLite、应用层加密、手动解锁、版本更新与密文备份恢复。系统解锁留出文档描述的接口，实际平台集成按目标环境验证。

## Decisions

- 用成熟库实现每版本 DEK 和根密钥包装，将凭证标识、版本及格式绑定到认证数据；SQL 只写密文与非秘密元数据。
- 先写新版本并校验，再用事务切换当前版本。每次读取完整组合，避免并发更新时取到混合字段。
- 密文备份包含后续恢复所需元数据；恢复保持锁定，恢复出来的 Binding、Grant 或设备授权交给授权模块复核。会话、许可以及缓存不恢复。

## Dependencies

[p0-broker-gateway-helper](../p0-broker-gateway-helper/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/encrypted-vault/spec.md)和[执行清单](tasks.md)。
