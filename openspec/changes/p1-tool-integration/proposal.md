# P1 · 适配声明、接入迁移与恢复

## Why

工具接入会修改用户配置。必须让用户看到计划并保护无关字段，同时在失败时保留可恢复的状态。

## What Changes

实现严格的适配器 Manifest、工具探测、脱敏预览、导入、配置应用、验证、漂移识别和撤销。

## Capabilities

### New Capabilities

- `managed-tool-integration` — P1 · 适配声明、接入迁移与恢复

### Modified Capabilities

无。

## Impact

- 前置变更：[p1-http-gateway](../p1-http-gateway/proposal.md)、[p1-runtime-delivery](../p1-runtime-delivery/proposal.md)。
- 依据：[v0.1 实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 2、8、9.1、10.3、12.1、15.2 节。
