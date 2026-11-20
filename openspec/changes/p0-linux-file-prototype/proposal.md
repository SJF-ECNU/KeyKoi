# P0 · Linux 私有内存文件原型

> **延期**：本轮验收范围为本机原生 macOS。此 Linux 变更保留为后续规划，当前暂停实现与验收。

## Why

固定路径工具可能在配置旁写缓存，或通过临时文件和重命名更新配置。需要在 Linux 验证目录级视图与清理能力。

## What Changes

用实际 Linux 环境和小型测试工具验证文件系统行为，真实固定路径 CLI 的接入由 P2 完成。

## Capabilities

### New Capabilities

- `linux-file-isolation-prototype` — P0 · Linux 私有内存文件原型

### Modified Capabilities

无。

## Impact

- 前置变更：无前置变更。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 7.6、13、15.3、16.2 节。
