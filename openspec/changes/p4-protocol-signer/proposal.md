# P4 · 专用签名适配

## Why

依赖请求内容的签名不能用简单 Header 替换完成。需要针对有实际需求的单一服务协议验证。

## What Changes

从实际需求选择一个明确协议，实现已登记的外部 signer 或专用请求签名。支持范围随该协议记录。

## Capabilities

### New Capabilities

- `registered-protocol-signer` — P4 · 专用签名适配

### Modified Capabilities

无。

## Impact

- 前置变更：[p1-local-session-broker](../p1-local-session-broker/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 7.7、8、9.2、15.5、16.1 节。
