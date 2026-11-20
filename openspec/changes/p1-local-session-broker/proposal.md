# P1 · 本机会话、授权 Broker 与审计

## Why

网关、Helper 和运行器需要同一条授权路径，使本机用户或工具只能按登记目标和授予模式用钥。

## What Changes

实现受认证的本机 IPC、Session、Grant、UseLease、内部 Resolver、短期中介令牌和元数据审计。

## Capabilities

### New Capabilities

- `local-session-broker` — P1 · 本机会话、授权 Broker 与审计

### Modified Capabilities

无。

## Impact

- 前置变更：[p1-encrypted-vault](../p1-encrypted-vault/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 4、6、8.4、9、11、12.3、12.5 节。
