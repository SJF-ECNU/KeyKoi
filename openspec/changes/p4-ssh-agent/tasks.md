# P4 · SSH Agent 适配执行清单

验收依据为[规格场景](specs/managed-ssh-agent/spec.md)。本轮在当前 Mac 的原生 macOS 环境执行，见[验收口径](../../roadmap.md#验收口径)。

## 1. 实现

- [x] 1.1 实现受保护的本地 SSH Agent、授权枚举和支持算法签名。

## 2. 验收

- [x] 2.1 用真实 OpenSSH 客户端和受控服务器验证枚举、认证、撤销后的新连接，以及现有连接和日志边界。
