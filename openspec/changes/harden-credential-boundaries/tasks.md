## 1. 实现与实测

- [x] 1.1 更新 Go 和 x/crypto，验证构建、模块与漏洞复扫。
- [x] 1.2 加固 IPC 关闭、撤销和审计读取，验证普通主体和管理员的正常清理。
- [x] 1.3 实现并验证 MongoDB 上游 TLS、CA 及显式明文兼容。
- [x] 1.4 验证 OpenSpec 和工作记录。

## 验证记录

Go 最低版本为 1.26.11，x/crypto 为 v0.59.0。Go 模块校验通过。govulncheck v1.10.0 使用 2026-11-11 更新的 Go 漏洞库，扫描 `./...` 和 `./cmd/...` 均无发现。定向 Go 测试通过。临时守护进程实测 Unix IPC 会话关闭与现有 `keykoi audit` 正常。真实 Redis/MySQL/MongoDB 验收共 36 项通过且无跳过。
