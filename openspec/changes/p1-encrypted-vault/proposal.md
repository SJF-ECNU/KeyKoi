# P1 · 单机加密密钥库

## Why

单机版需要让指定数据库提供唯一权威的凭证组合版本，并让锁定、轮换、备份恢复具有可验证语义。

## What Changes

实现 SQLite、应用层加密、手动解锁、版本更新与密文备份恢复。系统解锁留出文档描述的接口，实际平台集成按目标环境验证。

## Capabilities

### New Capabilities

- `encrypted-vault` — P1 · 单机加密密钥库

### Modified Capabilities

无。

## Impact

- 前置变更：[p0-broker-gateway-helper](../p0-broker-gateway-helper/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 5、6、12.2、12.4、15.2 节。
