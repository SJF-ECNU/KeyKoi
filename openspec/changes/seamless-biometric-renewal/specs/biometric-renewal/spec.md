## ADDED Requirements

### Requirement: Early biometric helper renewal

系统 SHALL 默认每日及登录时检查描述文件，并只采用通过签名与权限检查且延长有效期的续签候选。

#### Scenario: Apple returns a cached profile

- **WHEN** 续签候选的到期时间与有效助手相同或更早
- **THEN** 保留有效助手并报告待重试，下一次计划检查再次尝试

#### Scenario: A new profile is installed

- **WHEN** Apple 签发有效期更长的候选且签名与原身份一致
- **THEN** 替换助手，并保留现有 Keychain 条目和 KeyKoi 服务运行状态
