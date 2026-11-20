# P4 · 数据库协议代理设计

## Context

通用 TCP 转发无法代替数据库协议的认证握手。需要按具体数据库驱动与协议验证代理用钥。

## Goals / Non-Goals

选定一个数据库协议，优先评估 PostgreSQL。支持向登记数据库认证及正常传输，业务 SQL 权限由原数据库负责。

## Decisions

- Broker 分开校验客户端会话与服务端 Binding，代理负责两端协议认证、上游 TLS、连接关闭和取消。
- 初期仅声明实测的客户端、驱动、认证方式和连接语义。数据库密码只用于受信上游认证。

## Dependencies

[p1-local-session-broker](../p1-local-session-broker/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/database-protocol-proxy/spec.md)和[执行清单](tasks.md)。
