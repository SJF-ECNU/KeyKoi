# P4 · 工具级受信 HTTPS 代理设计

## Context

有些工具支持配置代理但不能改 endpoint。对这类工具单独验证用户明确授权的域名和信任范围。

## Goals / Non-Goals

限定到用户自有或授权的客户端与登记服务，交付工具级代理与信任配置；证书固定或缺少独立信任配置时记录不支持。

## Decisions

- 用户明确选择工具和登记的目标域名，CA 私钥由密钥库保管。客户端只安装公开 CA，优先限定在工具配置中；上游始终验证证书。
- 将登记目标和 proxy 许可检查复用到注入路径。普通 CONNECT、未登记目标和证书固定分别明确处置；协议自身签名需要已验证的专用适配。

## Dependencies

[p1-management-release](../p1-management-release/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/tool-trusted-https-proxy/spec.md)和[执行清单](tasks.md)。
