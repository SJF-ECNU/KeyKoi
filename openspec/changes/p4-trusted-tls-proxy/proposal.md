# P4 · 工具级受信 HTTPS 代理

## Why

有些工具支持配置代理但不能改 endpoint。对这类工具单独验证用户明确授权的域名和信任范围。

## What Changes

限定到用户自有或授权的客户端与登记服务，交付工具级代理与信任配置；证书固定或缺少独立信任配置时记录不支持。

## Capabilities

### New Capabilities

- `tool-trusted-https-proxy` — P4 · 工具级受信 HTTPS 代理

### Modified Capabilities

无。

## Impact

- 前置变更：[p1-management-release](../p1-management-release/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 7.9、8、13.1、16.1 节。
