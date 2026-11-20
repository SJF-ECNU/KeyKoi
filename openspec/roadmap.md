# KeyKoi 实施路线图

依据 [KeyKoi v0.1 实施设计草案](../KeyKoi_Implementation_Plan_v0.1.md) 第 15–17 节。每项变更包含 proposal、design、需求场景和 tasks。实施时在对应 tasks 中记录进度。本轮验收以这台 Mac 的原生 macOS 环境为准。

**实施状态（2026-11-19）**：P0、P1 六项、P3 与 P4 五项已实现并在本机 macOS 验收，`tasks.md` 已按证据勾选；Linux 两项与 Windows 延期。证据、限制与复测命令见 [验收总览](../docs/验收/验收总览.md)。

## 开工顺序

先执行 **P0 用钥协议、HTTP 与真实 Helper 原型**。P0 主线的字段、流程和测量结果用于 P1。P1 的网关和运行时交付在 Broker 可用后可并行。P3 使用本机多进程验证中心功能，按 P1 单机交付推进。

| 阶段与变更 | 前置变更 | 验收结果 |
| --- | --- | --- |
| [P0 · 用钥协议、HTTP 与真实 Helper 原型](changes/p0-broker-gateway-helper/proposal.md) | 无 | 四个核心对象、受控 HTTP 网关、真实 Helper 缓存情况、直连与代理测量 |
| [P1 · 单机加密密钥库](changes/p1-encrypted-vault/proposal.md) | P0 主线 | 加密持久化、解锁、原子轮换、锁定状态下的密文备份恢复 |
| [P1 · 本机会话与 Broker](changes/p1-local-session-broker/proposal.md) | 加密密钥库 | 本地认证、最小许可、内部取钥、撤销、元数据审计 |
| [P1 · 显式 HTTP 网关](changes/p1-http-gateway/proposal.md) | 本机会话与 Broker | 真实 HTTP 工具的登记目标认证、状态及流式响应 |
| [P1 · 原生 Helper 与环境交付](changes/p1-runtime-delivery/proposal.md) | 本机会话与 Broker | 原生命令实跑、受限交付、取消与清理 |
| [P1 · 适配器与工具迁移](changes/p1-tool-integration/proposal.md) | HTTP 网关、运行时交付 | 工具探测、脱敏预览、导入、配置应用、验证、失败恢复及撤销 |
| [P1 · 单机管理、安装与发布验收](changes/p1-management-release/proposal.md) | 适配器与工具迁移 | 本机管理与安装、两条真实工具路径、实测性能和故障恢复 |
| [P3 · 多设备中心](changes/p3-central-device-broker/proposal.md) | P1 单机交付 | 两种中心部署路径、设备会话、版本一致性、远端撤销和断网时限 |
| [P4 · SSH Agent](changes/p4-ssh-agent/proposal.md) | 本机会话与 Broker | 真实 SSH 认证与撤销效果 |
| [P4 · 专用签名](changes/p4-protocol-signer/proposal.md) | 本机会话与 Broker | 一种真实协议的签名、越界拒绝及兼容范围 |
| [P4 · OAuth 登录与刷新](changes/p4-oauth-refresh/proposal.md) | HTTP 网关、多设备中心 | 一家提供方的登录、串行刷新、原子版本更新及失败恢复 |
| [P4 · 数据库协议代理](changes/p4-database-proxy/proposal.md) | 本机会话与 Broker | 一个数据库协议与真实驱动的认证、TLS 和生命周期 |
| [P4 · 工具级受信 HTTPS 代理](changes/p4-trusted-tls-proxy/proposal.md) | P1 单机交付 | 已授权工具与登记域名的信任配置、上游校验及撤回效果 |
| [审核缺陷修复](changes/review-remediation/proposal.md) | 全部已实现变更 | 按 2026-11-20 审核结论修复 15 项 P1 与 19 项 P2：授权与交付边界、代理上游传输、密钥库恢复、中心权限、OAuth 传输、接入与助手、CLI/运行器、网关与 macOS 安装 |

## 延期的 Linux 专项

以下变更保留设计和清单，暂不执行。Windows 的实现与验收也延期。

| 变更 | 前置变更 | 后续验收范围 |
| --- | --- | --- |
| [P0 · Linux 私有内存文件原型](changes/p0-linux-file-prototype/proposal.md) | 无 | 实测私有目录、文件替换、邻接文件、回收和宿主限制 |
| [P2 · Linux 受控文件运行](changes/p2-linux-controlled-runtime/proposal.md) | P0 Linux 原型、P1 工具迁移 | 一个真实固定路径 CLI 的文件隔离、写回检测、进程树和回收 |

## 验收口径

- [草案第 15 节](../KeyKoi_Implementation_Plan_v0.1.md#15-测试与验收) 是共同依据。用运行时生成的测试凭证跑链路。记录真实工具版本、系统、适配器版本、运行环境、实际扫描范围与结果。P0 先测协议和风险，P1 以后以真实工具验证兼容。
- 本轮应用、真实工具、安装包、验收依赖和性能测量均在本机原生 macOS 运行。验收记录写明实际 macOS 版本、芯片架构、工具与依赖版本。适配器兼容结论只覆盖实际验过的组合。
- P3 在本机运行中心服务、PostgreSQL 和两个独立注册的设备客户端实例；各实例使用独立身份和状态目录。验证设备许可与断连、重连、撤销等协议行为，性能结果标明为本机拓扑，跨物理主机表现待后续验证。
- 真实工具与账户的验收条件、P4 的首个协议目标按对应任务确定。P0 测量后再填写发布性能门槛。
