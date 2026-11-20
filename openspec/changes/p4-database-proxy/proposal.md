# P4 · 数据库协议代理

## Why

通用 TCP 转发无法代替数据库协议的认证握手。需要按具体数据库驱动与协议验证代理用钥。

## What Changes

选定一个数据库协议，优先评估 PostgreSQL。支持向登记数据库认证及正常传输，业务 SQL 权限由原数据库负责。

## Capabilities

### New Capabilities

- `database-protocol-proxy` — P4 · 数据库协议代理

### Modified Capabilities

无。

## Impact

- 前置变更：[p1-local-session-broker](../p1-local-session-broker/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 7.10、9.2、15、16.1 节。
