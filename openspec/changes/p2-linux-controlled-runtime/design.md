# P2 · Linux 受控文件运行与旧 CLI设计

> **延期**：本轮验收范围为本机原生 macOS。此 Linux 变更保留为后续规划，当前暂停实现与验收。

## Context

固定路径和可指定配置路径的 CLI 需要受控视图处理凭证、相邻文件及写回。P0 的 Linux 结论决定具体支持范围。

## Goals / Non-Goals

交付 Linux 可指定路径内存配置、固定路径私有视图、写回检测和进程树清理，并通过一个真实固定路径 CLI 验收。macOS、Windows 独立评估。

## Decisions

- 运行器按适配声明生成结构化配置，覆盖所需目录，限制容量和写入范围。对挂载、swap、转储及运行权限按实际环境核验；无法满足时拒绝启动。
- 需额外权限的操作限制在受信配置允许的挂载与清理范围，CLI 继续以原用户或明确受限身份运行。
- 支持临时文件重命名、邻接缓存、文件锁和异常退出检查；观察到写回后按适配规则处置，无任何明文磁盘降级。

## Dependencies

[p0-linux-file-prototype](../p0-linux-file-prototype/proposal.md)、[p1-tool-integration](../p1-tool-integration/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/linux-controlled-file-runtime/spec.md)和[执行清单](tasks.md)。
