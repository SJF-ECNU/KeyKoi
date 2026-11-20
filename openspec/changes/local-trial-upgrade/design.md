---
workstream: local-trial-upgrade
---

## Context

现有安装由 launchd 管理。新代码已通过 [[docs/验收/验收总览#2026-11-21 安全与易用性合并复测]]。本次工作流见 [[project-memory/工作流/本机试用升级]]。

## Goals / Non-Goals

以本地 Git 快照构建试用版，保留上版程序、进程配置及一致的密文库。临时库做恢复和回滚，避免真实库降级。只对现有工具执行可验证的常规操作。

## Decisions

- 使用独立本地 Git 分支保存候选提交，保持原工作树。
- 通过 KeyKoi 生成密文备份，并以 SQLite online backup 取得可直接回退的数据库副本。校验副本后才替换程序。
- 临时库分别验证恢复后的锁定、旧会话失效和旧授权待复核，再用旧程序及其数据库副本启动。
- 在真实终端输入主密码，交互式 Touch ID 验收优先使用独立临时账号。保留现有 helper、续签任务和安装地址。

## Risks / Trade-offs

重启会关闭旧会话。现有 MongoDB 如依赖明文需先识别，避免静默改动；Touch ID 结果取决于当前 macOS 登录会话、签名和现场确认。执行详见 [tasks.md](tasks.md)。

## 恢复入口

首个试用版从本地分支 `codex/local-trial-2026-11-21` 的提交 `d459739` 构建，使用 Go 1.26.11。升级前备份位于 `~/Library/Application Support/KeyKoi/rollback/20261121-002353-local-trial/`，包含旧 CLI、daemon、适配器、launchd 配置、密文导出和经 SQLite 一致性校验的在线副本。

回退程序时使用备份中的旧二进制和适配器，重启原 launchd 作业并交互解锁。只有需要把数据也回退到升级前时才使用 SQLite 副本。先停服务并另存当前库及其 WAL/SHM，再用一致快照启动旧版，以免覆盖升级后的写入。密文导出走 `keykoi restore`，恢复后先锁定，旧授权需要重新确认。
