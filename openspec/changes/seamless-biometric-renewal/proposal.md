## Why

七天描述文件和每周检查之间没有故障余量。Xcode 重用缓存时，重建也未必延长可用窗口。

## What Changes

- 每日和登录时检查，在到期前重试。
- 续签使用 Apple 正式签发，确认到期时间真正推进后热替换助手。
- 保持现有签名身份、Keychain 存取边界和主服务运行。

## Capabilities

### New Capabilities

- `biometric-renewal`：到期前后台续签。

### Modified Capabilities

无。

## Impact

macOS 续签脚本、LaunchAgent 和对应文档。
