## Why

固定提交审查发现了凭证交付、默认传输、撤销并发、配置保留和备份一致性缺陷。

## What Changes

- 约束协议重写与凭证交付，统一安全传输策略。
- 修复授权提交、锁库、恢复与备份的并发边界。
- 修复本地接入、shim 和 TLS 响应行为。

## Capabilities

### New Capabilities

- `review-delivery-safety`: 凭证交付、代理和库操作的安全边界。

## Impact

影响 daemon、Broker、数据库代理、TLS 代理、Vault、Store 和本地适配器。
