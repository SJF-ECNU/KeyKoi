# P2 · Linux 受控文件运行与旧 CLI

> **延期**：本轮验收范围为本机原生 macOS。此 Linux 变更保留为后续规划，当前暂停实现与验收。

## Why

固定路径和可指定配置路径的 CLI 需要受控视图处理凭证、相邻文件及写回。P0 的 Linux 结论决定具体支持范围。

## What Changes

交付 Linux 可指定路径内存配置、固定路径私有视图、写回检测和进程树清理，并通过一个真实固定路径 CLI 验收。macOS、Windows 独立评估。

## Capabilities

### New Capabilities

- `linux-controlled-file-runtime` — P2 · Linux 受控文件运行与旧 CLI

### Modified Capabilities

无。

## Impact

- 前置变更：[p0-linux-file-prototype](../p0-linux-file-prototype/proposal.md)、[p1-tool-integration](../p1-tool-integration/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 7.5、7.6、10.2、13、15.3、16.1 节。
