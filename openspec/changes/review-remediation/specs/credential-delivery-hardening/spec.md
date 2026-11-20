## ADDED Requirements

### Requirement: 原始凭证只对运行时交付开放

中介 SHALL 只在 `runtime_delivery` 模式下通过通用解析接口返回原始凭证字段。`sign` 许可的 SSH 材料 SHALL 由只返回该凭证类型所需字段的专用接口交付，响应不得包含无关密钥字段。

#### Scenario: sign 模式请求通用解析

- **WHEN** 调用方以 `sign` 许可请求 `/v1/resolve`
- **THEN** 请求被拒绝并返回 `USE_NOT_ALLOWED`，不返回任何字段

#### Scenario: SSH 签名材料只含密钥字段

- **WHEN** 持有有效 `sign` 许可的 SSH Agent 请求签名材料
- **THEN** 响应只包含 `private_key` 与可选的 `private_key_passphrase`

### Requirement: 交付前重新校验

中介 SHALL 在交付凭证前重新核对该次授权的会话、授权代次、授权状态、绑定与凭证版本；任一项变化 SHALL 阻止交付并撤销本次许可。

#### Scenario: 验证期间撤销授权

- **WHEN** 授权判定后、交付前撤销了该授权
- **THEN** 交付被拒绝，许可不产生真实字段

#### Scenario: 验证期间轮换凭证

- **WHEN** 后台验证进行中凭证切换到新版本
- **THEN** 交付使用新版本或拒绝，不得返回旧版本与旧许可组合

### Requirement: 代理使用主服务的用钥决定

TLS 代理与数据库代理 SHALL 把用钥决定交给主服务，SHALL NOT 自建绕过锁定与验证的独立授权路径。转发 SHALL 使用同一次授权返回的目标与凭证版本。

#### Scenario: 主库锁定后代理请求用钥

- **WHEN** 主密钥库已锁定，客户端经代理发起上游连接
- **THEN** 连接被拒绝并返回锁定错误

#### Scenario: 绑定在途变更

- **WHEN** 请求在途时绑定目标发生变化
- **THEN** 既有连接被结束或按新绑定重新校验，不使用旧目标配新凭证

### Requirement: 上游传输可验证

数据库代理 SHALL 对上游默认使用可验证的 TLS。降级为明文 SHALL 要求显式配置。Redis 认证前解析 SHALL 设长度与嵌套上限。

#### Scenario: Redis 明文上游

- **WHEN** 上游地址为明文且未声明允许降级
- **THEN** 代理拒绝连接并返回配置错误

#### Scenario: MongoDB 认证前握手

- **WHEN** 客户端在认证前请求 hello
- **THEN** 代理返回有效的 minWireVersion 与 maxWireVersion，真实 mongosh 能进入 SASL 认证而不是报告 wire version undefined

### Requirement: 备份与恢复保护现有密钥库

备份 SHALL NOT 覆盖现有数据库文件，写入 SHALL 原子完成。恢复 SHALL 在完整校验通过后整体替换。每个密钥库 SHALL 保存独立的根密钥校验依据。

#### Scenario: 空库恢复后使用旧生物识别登记

- **WHEN** 恢复到另一套空库后沿用旧系统登记解锁
- **THEN** 登记因校验依据不匹配被拒绝，并要求重新登记

### Requirement: 权限分离与版本约束（中心）

中心 SHALL 分离设备注册凭据与管理凭据，SHALL 按主体、方式与凭证版本裁定许可。代次失效 SHALL 与真正撤销区分，客户端只对可安全重新申请的失效做一次有界重试。

#### Scenario: 设备注册凭据请求管理操作

- **WHEN** 使用设备注册凭据调用策略写入接口
- **THEN** 请求被拒绝并返回权限错误

### Requirement: OAuth 传输与状态保护

通用 OAuth 客户端 SHALL 默认要求 HTTPS 并禁止令牌交换跳转。回调 SHALL 保留发起后管理员设置的停用状态与版本预期。

#### Scenario: 发起后停用

- **WHEN** 登录发起后管理员停用该凭证，随后回调到达
- **THEN** 记录保持停用

#### Scenario: 提交后重新激活前停用

- **WHEN** 回调已提交新令牌版本，管理员在重新激活前停用该凭证
- **THEN** 状态更新因 revision 预期不匹配而失败，最终记录保持停用

### Requirement: 本机进程与路径语义

Unix 监听 SHALL 不替换存活 socket。shim 与主 CLI SHALL 共用数据目录解析。全局参数解析 SHALL 在 `--` 处停止，SHALL 按信号映射退出码。

#### Scenario: 第二个实例启动

- **WHEN** 后台服务运行中再次启动实例或配置 SSH Agent
- **THEN** 运行中的套接字保持可用，新实例报告地址占用

### Requirement: 网关状态与路径一致

网关 SHALL 把验证失败映射为可处理的 HTTP 状态。路径范围判定 SHALL 使用与上游一致的规范化路径。响应中断 SHALL 记为传输失败。

#### Scenario: 验证失败

- **WHEN** 用钥需要验证但验证不可用
- **THEN** 客户端收到可处理的错误状态与稳定错误码，而不是 500
