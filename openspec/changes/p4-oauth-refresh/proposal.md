# P4 · OAuth 登录与刷新

## Why

OAuth access token 会过期，refresh token 轮换还可能使旧版本失效。需要提供方级的登录、刷新和回收路径。

## What Changes

对一个明确提供方实现受信登录、中心串行刷新、组合更新和代理使用 access token。闭源客户端通用登录态导入超出该变更范围。

## Capabilities

### New Capabilities

- `managed-oauth-refresh` — P4 · OAuth 登录与刷新

### Modified Capabilities

无。

## Impact

- 前置变更：[p1-http-gateway](../p1-http-gateway/proposal.md)、[p3-central-device-broker](../p3-central-device-broker/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 5.1、7.11、11.3、12.2、16.1 节。
