# P1 · 原生 Helper 与环境变量交付

## Why

有些工具必须自己拿到真实值并完成认证。Helper 与环境变量启动器需要限制交付范围并保留原命令体验。

## What Changes

用同一个内部 Resolver 实现一个真实原生 Helper、子进程环境注入和可验证的进程生命周期。P2 的 Linux 固定路径内存能力属于延期规划。

## Capabilities

### New Capabilities

- `native-runtime-delivery` — P1 · 原生 Helper 与环境变量交付

### Modified Capabilities

无。

## Impact

- 前置变更：[p1-local-session-broker](../p1-local-session-broker/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 7.3、7.4、9.2、10.2、10.3、15.3、15.4 节。
