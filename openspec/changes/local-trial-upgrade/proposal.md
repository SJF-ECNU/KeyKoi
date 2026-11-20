## Why

把已通过隔离验收的安全与易用性改动整理成可重建的本机试用版，并核对现有工具、主密码和 Touch ID 在实际安装下的表现。

## What Changes

- 保存本地源代码版本及升级前的密文保险库、程序和适配配置。
- 先在临时保险库实测备份恢复及退回旧版，再重启本机现有服务。
- 在本机交互解锁后验证已接入工具和 Touch ID。

## Capabilities

### New Capabilities

- `local-trial-upgrade`：可复验并可回退的本机试用升级过程。

### Modified Capabilities

无。

## Impact

更新本机 CLI、daemon、适配声明和运行中的 SSH Agent。保留安装位置、现有凭证和授权配置。不推送或发布远端。
