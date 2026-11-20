# P4 · SSH Agent 适配设计

## Context

SSH 客户端已有委托签名接口，可以将私钥留在中介的可信范围内。

## Goals / Non-Goals

实现受保护的 SSH Agent 枚举和签名，以实际客户端确认兼容。导入、删除和替换继续走管理能力。

## Decisions

- 按本地对端访问权限和 sign 许可控制接口，只枚举其可用托管密钥。
- 以登记的密钥类型和算法生成认证签名；日志不记录私钥、完整待签数据或签名材料。

## Dependencies

[p1-local-session-broker](../p1-local-session-broker/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/managed-ssh-agent/spec.md)和[执行清单](tasks.md)。
