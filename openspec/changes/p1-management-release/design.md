# P1 · 单机管理、安装与发布验收设计

## Context

单机版需要独立可安装，使用者能从录入、接入、验证一路走到轮换、锁定与故障恢复。

## Goals / Non-Goals

交付本机管理 CLI 和 Web UI、后台启动、安装包及实际工具验收报告。本轮交付与验收以本机 macOS 为准。

## Decisions

- 管理入口复用受保护的本地能力；Web UI 仅本机可访问并校验 Host、Origin 和请求伪造风险。秘密通过受控交互输入，日常查看和审计只返回元数据。
- 管理体验覆盖初始化解锁、导入、接入预览、启用、停用、轮换、诊断和恢复。展示目标、接入模式、真实值交付、已验证版本、解锁要求及最新验证结果。
- Release 复跑真实 HTTP 客户端和真实运行时工具，记录安装、锁定、异常退出、密文恢复、延迟与清理结果。性能阈值根据 P0 数据与本阶段复测填写；中心不可用语义由 P3 验证，单机数据不依赖中心。

## Dependencies

[p1-tool-integration](../p1-tool-integration/proposal.md)。前置变更提供的运行行为和相应验收证据用于本变更的实现与验证。全局顺序见[实施路线图](../../roadmap.md)。

## Verification

见[需求场景](specs/standalone-management-release/spec.md)和[执行清单](tasks.md)。
