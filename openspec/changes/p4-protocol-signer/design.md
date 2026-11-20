# P4 · 专用签名适配设计

## Context

依赖请求内容的签名不能用简单 Header 替换完成。需要针对有实际需求的单一服务协议验证。

## Goals / Non-Goals

从实际需求选择一个明确协议，实现已登记的外部 signer 或专用请求签名。支持范围随该协议记录。

## Decisions

- 使用服务协议定义的规范化输入，校验签名用途、目标、请求体摘要和完整凭证版本。
- 对离线预签名、分块和大文件分别声明是否支持，验证已声明路径。预签名结果可授予临时访问，禁止写入普通日志。

## Dependencies

[p1-local-session-broker](../p1-local-session-broker/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/registered-protocol-signer/spec.md)和[执行清单](tasks.md)。
