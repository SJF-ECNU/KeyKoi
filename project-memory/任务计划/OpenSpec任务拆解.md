---
type: task-plan
project: KeyKoi
workstream: openspec-planning
status: completed
updated_at: 2026-11-19
---

# OpenSpec 任务拆解计划

关联工作流：[[project-memory/工作流/OpenSpec任务拆解]]。

将 [[KeyKoi_Implementation_Plan_v0.1|实施设计草案]] 转化为 P0–P4 的依赖路线和可独立执行的 OpenSpec 变更。本任务交付计划、需求场景和验收任务，开发进度统一记入各变更的 tasks.md。

1. 按草案第 15–17 节拆分阶段、能力与交付依赖。验收为路线图覆盖各阶段并指出起始项。
2. 用 OpenSpec 初始化本地项目并落盘提案、设计、规格与任务。验收为每个变更的四类产物齐备，任务有可核验结果。
3. 严格校验变更、依赖关系和导航，记录下一项开发工作。


## 验收结果

- 路线图覆盖 P0–P4，具备 15 个变更及无循环的前置依赖。
- 每项变更均落盘 proposal、design、spec 和 tasks，共 26 项需求、29 个场景、62 项待执行任务。
- 严格校验 15 项通过。下一项为 [P0 主线任务 1.1](../../openspec/changes/p0-broker-gateway-helper/tasks.md#1-实现)。

## 本机 Mac 验收范围修订

将本轮验收统一到当前 Mac 的原生 macOS 环境。同步设计草案、OpenSpec 入口和直接受影响的任务，明确 Linux 专项延期、P3 本机进程拓扑，并复核规范和链接。

修订完成。15 项 OpenSpec 严格校验通过，13 个变更按本机 Mac 验收，2 个 Linux 专项登记为延期。
