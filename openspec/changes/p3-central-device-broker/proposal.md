# P3 · 多设备中心、许可与撤销

## Why

多设备需要共享权威存储并获得可撤销的用钥许可。中心故障或失联时，本机必须遵循明确截止时间。

## What Changes

交付 PostgreSQL 中心服务、受认证设备连接、中心存储与本机认证、中心认证执行、失效事件与断网规则。

## Capabilities

### New Capabilities

- `central-device-broker` — P3 · 多设备中心、许可与撤销

### Modified Capabilities

无。

## Impact

- 前置变更：[p1-management-release](../p1-management-release/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 3.3、4.5、5、11.3、12.2–12.4、16.1 节。
