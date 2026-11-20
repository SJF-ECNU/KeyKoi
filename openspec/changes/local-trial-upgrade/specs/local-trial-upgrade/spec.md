## ADDED Requirements

### Requirement: Local Upgrade Recovery

本机升级 SHALL 保留可重建的候选源码、旧程序、适配器、启动配置和一致的密文数据库。

#### Scenario: Recovery rehearsal

- **WHEN** 在临时保险库执行恢复和降级
- **THEN** 恢复后保险库先锁定，旧授权待复核，并能使用保存的旧程序和升级前数据重新启动

### Requirement: Local Trial Verification

本机试用升级 SHALL 记录已接入工具、交互解锁和 Touch ID 的实际验证结果。

#### Scenario: User unlock after restart

- **WHEN** 新服务重启且用户在本机终端输入主密码
- **THEN** 新服务解锁，测试已接入工具，并记录 Touch ID 是否完成和任何需要现场操作的限制
