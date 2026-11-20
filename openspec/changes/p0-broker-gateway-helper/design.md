# P0 · 用钥协议、HTTP 与真实 Helper 原型设计

## Context

先验证两条最短用钥链路，给 P1 的授权接口、适配方式和性能复测提供证据。

## Goals / Non-Goals

用 Go 做内存 Broker、显式 HTTP 原型和一个真实 Helper 集成，持久密钥库、正式管理服务和系统级隔离由后续变更交付。

## Decisions

- Credential 表示同版本凭证组合；Binding 包含凭证引用、登记 origin、认证方式与适配器；Session 绑定已认证主体和到期时间；UseLease 绑定会话、Binding、交付模式与截止时间。原型用显式测试实例和运行时生成凭证，授权先于取值。
- HTTP 先验证会话和目标，再移除中介令牌并注入一类上游 Header；用受控测试上游检查流式行为和实际发送字段。
- Helper 使用一个真实工具，优先验证 AWS CLI credential_process。用隔离的 profile 和受控上游验证实际调用，记录读取通道和新增缓存，按工具真实凭证有效期输出。
- 记录相同环境下的直连与代理时间、流式首块到达和测试条件。支持文案分别展示 proxy、sign、runtime_delivery 与 planned/experimental/verified，指出工具何时拿到真实值。

## Dependencies

无前置变更。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/broker-gateway-helper-prototype/spec.md)和[执行清单](tasks.md)。
