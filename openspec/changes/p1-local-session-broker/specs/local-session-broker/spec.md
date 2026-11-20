## ADDED Requirements

### Requirement: 本机身份与最小许可

Broker SHALL 验证本机对端、登记 Binding、Grant、交付模式和三个有效期边界，且仅向可信执行通道提供真实凭证。

#### Scenario: 缺少相应许可

- **WHEN** 请求只凭引用、本机地址、自报身份或 proxy 许可申请 runtime_delivery
- **THEN** 拒绝取钥，返回不带秘密的稳定错误

#### Scenario: 独立管理权

- **WHEN** 持普通用钥权限的本机会话发出管理请求
- **THEN** 管理请求被拒绝

### Requirement: 撤销和元数据审计

Broker SHALL 让锁定、停用、撤销及凭证切换阻止旧授权路径发起新用钥，并记录允许的审计元数据。

#### Scenario: 撤销后调用

- **WHEN** 会话所属许可已撤销或后台已重启
- **THEN** 旧会话或令牌无法用钥，日志不含令牌或业务凭证
