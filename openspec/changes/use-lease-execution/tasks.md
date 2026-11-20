## 1. 执行

- [x] 1.1 Broker 复核原许可，并保留现有撤销入口。
- [x] 1.2 四种数据库代理把释放点移至连接结束，共享期限与撤销检查。
- [x] 1.3 透明 HTTPS 代理由 daemon 执行，使用客户端会话与 proxy 授权。

- [x] 1.4 给原始材料交付增加绑定级字段白名单，统一原生协议目标解析。

## 2. 验证

- [x] 2.1 Go 测试、race、协议验收与 OpenSpec 校验。

构建、vet、全量测试、race 与 OpenSpec strict 校验通过。验收共 120 项：Redis/MySQL/MongoDB 34（含撤销后现有 Redis 连接关闭）、PostgreSQL 15、TLS 代理 24、SSH Agent 32、中心 15。

## 3. 全仓库实现整理

- [x] 3.1 审查生产代码的重复实现，收拢数据库授权与快照校验、HTTP 转发和 IPC 会话创建，保留协议行为与错误边界。
- [x] 3.2 运行全量 Go 测试、race、vet 与相关协议验收。

整理后全量 Go 测试、race 与 vet 通过。Redis/MySQL/MongoDB 34/34，TLS 代理 24/24。
