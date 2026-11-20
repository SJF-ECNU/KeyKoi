## ADDED Requirements

### Requirement: 可读的近期使用记录

本机管理页 SHALL 显示近期用钥记录的时间、主体、绑定、模式和结果，支持按主体与结果筛选。使用视图 SHALL 只返回结构化审计元数据。

#### Scenario: 查看近期调用

- **WHEN** 管理员连接管理页，且应用产生了用钥记录
- **THEN** 页面显示最新记录，可筛选，且授权结果与上游状态语义清楚

### Requirement: 按当前用户或 Codex 代理授权

管理页 SHALL 允许管理员以可读名称选择当前账户、Codex App、Codex CLI 或 Claude Code，按绑定与交付模式发放和撤销授权。代理身份 SHALL 来自本机连接的进程信息。

#### Scenario: 给代理一个独立授权

- **WHEN** 管理员给 Codex App 发放特定 Binding 和模式的许可
- **THEN** 识别为 App 的调用可使用该许可；其他主体仍需自己的有效授权，撤销后该许可不再接受新用钥

#### Scenario: 已有本机账户授权

- **WHEN** 本机账户已有有效授权，且同账户下的已识别代理发起对应请求
- **THEN** 账户授权仍有效，记录保留实际识别到的代理主体

### Requirement: 通用 Agent 注册

管理 API SHALL 允许管理员按稳定标识、名称和原生可执行路径注册其他 Agent，保存独立主体供 Grant 选择。

#### Scenario: 登记并使用通用 Agent

- **WHEN** 管理员登记一个此前未登记的原生可执行文件并授权
- **THEN** 来自该进程链的用钥会话会归属该 Agent；登记之外的调用或自报身份无法取得该 Agent 的许可
