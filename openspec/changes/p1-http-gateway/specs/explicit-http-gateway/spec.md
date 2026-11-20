## ADDED Requirements

### Requirement: 登记目标与凭证传递

网关 SHALL 仅向已授权的登记目标注入认证信息，上游 SHALL NOT 收到 KeyKoi 会话令牌。

#### Scenario: 错误目标或证书

- **WHEN** 客户端提交任意目标、上游响应要求跨 origin 重定向或证书验证失败
- **THEN** 对应请求没有向未授权目标发送真实凭证

### Requirement: 原请求和流式响应

网关 SHALL 保留支持范围内的路径、查询和业务响应语义，并及时转发响应块。

#### Scenario: 流式业务响应

- **WHEN** 真实可配置 endpoint 客户端请求支持的流式服务
- **THEN** 客户端在完整响应结束前收到前段，状态和必要头按约定传播
