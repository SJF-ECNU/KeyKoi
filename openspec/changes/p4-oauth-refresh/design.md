# P4 · OAuth 登录与刷新设计

## Context

OAuth access token 会过期，refresh token 轮换还可能使旧版本失效。需要提供方级的登录、刷新和回收路径。

## Goals / Non-Goals

对一个明确提供方实现受信登录、中心串行刷新、组合更新和代理使用 access token。闭源客户端通用登录态导入超出该变更范围。

## Decisions

- 以 Credential 为单位协调刷新，把上游返回的新 token 组合原子写入，缓存不超过真实到期减时钟余量。
- 区分可恢复网络错误、撤销与重新登录。上游轮换已成功而本地提交失败时，进入可见恢复或重新授权状态。

## Dependencies

[p1-http-gateway](../p1-http-gateway/proposal.md)、[p3-central-device-broker](../p3-central-device-broker/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/managed-oauth-refresh/spec.md)和[执行清单](tasks.md)。
