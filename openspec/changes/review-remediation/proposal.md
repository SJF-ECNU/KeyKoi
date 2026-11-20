# 审核缺陷修复（P1 15 项 / P2 19 项）

## Why

[全项目代码与功能审核](../../../project-memory/任务计划/全项目代码与功能审核.md) 在 2026-11-20 登记了 15 项 P1 与 19 项 P2 缺陷。这些缺陷集中在三处边界：**谁可以取得真实凭证**、**凭证被送到哪个目标**、**本机状态在中断、恢复和改绑后是否仍然自洽**。仅靠文档说明无法消除，需要在用钥链路、代理转发、密钥库与工具集成层同步收敛。

## What Changes

按审核编号逐项修复，不改设计承诺：

- 原始凭证只对 `runtime_delivery` 交付开放；`sign` 模式不再经通用解析接口返回整组字段，SSH Agent 改走独立的签名材料接口，只返回该凭据类型需要的字段。
- 用钥决定在交付前重新核对会话、授权、绑定与凭证版本，撤销、停用、轮换与在途验证的竞态收敛到一次提交前校验。
- TLS 代理与数据库代理把用钥决定交回主服务，转发使用同一次授权返回的绑定与版本。
- Redis/MySQL 上游握手补齐可验证传输与认证前的资源上限。
- 中心区分设备注册与管理凭据，许可按主体、方式和版本申请并约束最终取值；代次失效与真正撤销分开处理。
- 备份与恢复改为原子写出、完整校验后提交，并为每个密钥库保存独立的根密钥校验依据。
- OAuth 通用客户端默认要求受验证的 HTTPS，令牌交换禁止跳转；回调不覆盖管理员随后的停用。
- 接入备份只保存受管字段，撤销只还原本次管理的字段。
- CLI 与 shim 共用一个数据目录解析，Unix 监听不替换运行中的 socket，`--` 之后的参数与信号退出码按语义处理。
- 网关把验证失败映射为可处理的 HTTP 状态，路径与响应中断分别判定。

## Capabilities

### New Capabilities

- `credential-delivery-hardening` — 修复后的取用、转发、恢复与集成边界

### Modified Capabilities

无。实现落在既有模块内，对外命令与路由保持兼容；新增接口只用于受信组件之间。

## Impact

- 代码：`internal/{broker,daemon,ssha,ipcclient,vault,store,central,tlsproxy,dbproxy,mysqlproxy,mongoproxy,redisproxy,oauth,integration,gateway,model,runner,shim,osruntime}`、`cmd/keykoi*`、`packaging/macos`。
- 依据：[审核结论](../../../project-memory/任务计划/全项目代码与功能审核.md#审核结论)、[实施设计草案](../../../KeyKoi_Implementation_Plan_v0.1.md) 第 7、9、12、13 节。
- 兼容性：会话令牌、路由与配置格式不变；`sign` 模式的 SSH 材料改由新接口交付，属内部协议调整。
- 验收：受影响包的 `go test`、`go build ./...`、现有 shell 验收与针对性新增用例。
