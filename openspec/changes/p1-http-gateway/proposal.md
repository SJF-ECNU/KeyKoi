# P1 · 显式 HTTP 网关

## Why

可配置 endpoint 的客户端适合由 KeyKoi 代为认证，同时保留原工具的业务响应和流式行为。

## What Changes

实现单机显式网关、短期中介令牌、Bearer/API Key/Basic Header 注入与响应转发。

## Capabilities

### New Capabilities

- `explicit-http-gateway` — P1 · 显式 HTTP 网关

### Modified Capabilities

无。

## Impact

- 前置变更：[p1-local-session-broker](../p1-local-session-broker/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 4.3、7.2、9.2、10.1、11.1、15 节。
