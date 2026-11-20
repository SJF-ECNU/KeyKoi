# P1 · 显式 HTTP 网关设计

## Context

可配置 endpoint 的客户端适合由 KeyKoi 代为认证，同时保留原工具的业务响应和流式行为。

## Goals / Non-Goals

实现单机显式网关、短期中介令牌、Bearer/API Key/Basic Header 注入与响应转发。

## Decisions

- 登记 Binding 固定上游 scheme、host、port 和允许路径；验证许可后从可信路由构造请求，先移除中介与内部控制头，再注入认证并验证上游 TLS。
- 保留原路径编码、重复查询参数、状态码和必要响应头。拒绝未支持的升级协议，不自动跨 origin 重定向或重试有副作用的请求。
- 业务响应保持兼容；中介自身错误使用可辨认且不携带秘密的错误封装。支持范围记录到具体客户端和运行环境。

## Dependencies

[p1-local-session-broker](../p1-local-session-broker/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/explicit-http-gateway/spec.md)和[执行清单](tasks.md)。
