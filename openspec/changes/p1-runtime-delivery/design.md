# P1 · 原生 Helper 与环境变量交付设计

## Context

有些工具必须自己拿到真实值并完成认证。Helper 与环境变量启动器需要限制交付范围并保留原命令体验。

## Goals / Non-Goals

用同一个内部 Resolver 实现一个真实原生 Helper、子进程环境注入和可验证的进程生命周期。P2 的 Linux 固定路径内存能力属于延期规划。

## Decisions

- Helper 只在协议约定的输出通道交付，参数使用引用，原平台到期时间与许可分别表示。首个真实工具优先沿用 P0；若选 Git，分别处理 get/store/erase。
- 启动器定位原二进制并按参数数组执行，按声明设置环境，保留 cwd、输出、退出码、信号及 TTY。父进程不修改全局环境或普通持久配置。
- 关联 Run 与完整生命周期，退出、取消和服务重启能核查清理。用真实工具的缓存行为限定兼容性。

## Dependencies

[p1-local-session-broker](../p1-local-session-broker/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/native-runtime-delivery/spec.md)和[执行清单](tasks.md)。
