## ADDED Requirements

### Requirement: 完整 OAuth 组合更新

OAuth 适配 SHALL 通过受信入口登录，为同一凭证串行刷新并原子保存完整新组合。

#### Scenario: 并发刷新与提交中断

- **WHEN** 两个请求触发同一凭证刷新，或提供方轮换后本地持久化中断
- **THEN** 同一时间只有一次刷新推进；中断可诊断并恢复或要求重新授权，refresh token 不进入工具普通配置
