# P0 · 用钥协议、HTTP 与真实 Helper 原型

## Why

先验证两条最短用钥链路，给 P1 的授权接口、适配方式和性能复测提供证据。

## What Changes

用 Go 做内存 Broker、显式 HTTP 原型和一个真实 Helper 集成，持久密钥库、正式管理服务和系统级隔离由后续变更交付。

## Capabilities

### New Capabilities

- `broker-gateway-helper-prototype` — P0 · 用钥协议、HTTP 与真实 Helper 原型

### Modified Capabilities

无。

## Impact

- 前置变更：无前置变更。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 4、7.2、7.3、15、16.2 节。
