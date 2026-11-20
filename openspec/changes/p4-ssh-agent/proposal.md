# P4 · SSH Agent 适配

## Why

SSH 客户端已有委托签名接口，可以将私钥留在中介的可信范围内。

## What Changes

实现受保护的 SSH Agent 枚举和签名，以实际客户端确认兼容。导入、删除和替换继续走管理能力。

## Capabilities

### New Capabilities

- `managed-ssh-agent` — P4 · SSH Agent 适配

### Modified Capabilities

无。

## Impact

- 前置变更：[p1-local-session-broker](../p1-local-session-broker/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 7.8、9.2、13.1、16.1 节。
