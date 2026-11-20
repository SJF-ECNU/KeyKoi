# P1 · 适配声明、接入迁移与恢复设计

## Context

工具接入会修改用户配置。必须让用户看到计划并保护无关字段，同时在失败时保留可恢复的状态。

## Goals / Non-Goals

实现严格的适配器 Manifest、工具探测、脱敏预览、导入、配置应用、验证、漂移识别和撤销。

## Decisions

- 声明记录工具版本、运行模式、字段映射、目标、读写范围和验证状态，执行交给内置或审核引擎。工作区声明无权放宽可信 Binding，模板不执行任意 shell。
- 顺序为检测、密文导入、配置替换、真实验证再启用。保留结构化恢复信息，含秘密的原配置仅按需加密保存。使用现有版本或受管字段比较避免覆盖并发修改。
- 配置改动后验证失败进入 recovery_required，只恢复非敏感配置和可恢复接入状态。漂移或未验证版本暂停 verified 状态。

## Dependencies

[p1-http-gateway](../p1-http-gateway/proposal.md)、[p1-runtime-delivery](../p1-runtime-delivery/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/managed-tool-integration/spec.md)和[执行清单](tasks.md)。
