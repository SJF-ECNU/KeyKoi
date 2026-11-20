---
workstream: seamless-biometric-renewal
---

## Context

复用已部署的 LaunchAgent 和 Xcode 自动签名。参考 [[docs/指南/生物识别助手续签与部署]]。

## Goals / Non-Goals

保留原助手访问组与签名团队。先在调用 Apple 自动签名的真实路径验证续签，再更新本机调度。七天为 Apple Personal Team 的签发规则。Apple 不可达、账户失效或电脑长期未登录时，保留现有主密码回退。

## Decisions

- 将默认每周检查调整为每天，并在 LaunchAgent 加载时检查一次。保留显式每周调度选项。
- 剩余不足三天就尝试正式签发。临时移出与当前助手文件完全一样的 Xcode 缓存条目，构建结束后恢复。候选必须有更晚的到期时间。成功部署后归档旧缓存，防止下一轮误用；复用同一文件时保留旧助手并记录待重试。
- 校验签名团队、助手访问组和描述文件后原子交换两个应用包。保留原路径，KeyKoi 服务与 Keychain 条目不变。
- 在不足一天且后台检查失败时尝试发一次系统通知。主密码继续可用。

本机旧 LaunchAgent plist 备份在 `~/Library/Application Support/KeyKoi/rollback/20261121-004310-biometric-renew/`。

见 [tasks.md](tasks.md)。
