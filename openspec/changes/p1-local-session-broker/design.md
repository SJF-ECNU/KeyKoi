# P1 · 本机会话、授权 Broker 与审计设计

## Context

网关、Helper 和运行器需要同一条授权路径，使本机用户或工具只能按登记目标和授予模式用钥。

## Goals / Non-Goals

实现受认证的本机 IPC、Session、Grant、UseLease、内部 Resolver、短期中介令牌和元数据审计。

## Decisions

- 本轮使用 macOS 的本地 IPC，并在本机验证对端身份与访问控制。管理权和用钥权独立评估；工具自报标签与本机地址仅是元数据。
- Lease 取会话、Grant 和原凭证有效期的上限。原平台有效期、许可截止和缓存截止分别保存。中介令牌只能借已授权会话交付给登记工具。
- 锁定、停用、撤销或版本切换使关联许可与缓存失效。审计只写允许的元数据，容量不足使用明确背压或拒绝。

## Dependencies

[p1-encrypted-vault](../p1-encrypted-vault/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/local-session-broker/spec.md)和[执行清单](tasks.md)。
