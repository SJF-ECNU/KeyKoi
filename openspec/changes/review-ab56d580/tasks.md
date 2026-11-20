## 1. 凭证交付与传输

- [x] 1.1 修复 Redis、SSH、TLS 客户端认证、PostgreSQL 默认传输与 OAuth（K01–K05）
- [x] 1.2 修复 Broker 提交与验证复用，核对中心主体（K06、K13、C2）

## 2. 可用性与持久化

- [x] 2.1 修复 Vault 状态、备份和恢复并发（K07、K10、C3）
- [x] 2.2 修复 TLS 默认端口与断流、配置漂移、shim、监听地址（K08、K09、K11、K12、K14）
- [x] 2.3 核对数据库连接撤销语义（C1）

## 3. 验证

- [x] 3.1 运行 OpenSpec 校验、Go 测试与 race 检查，记录兼容性和验证范围

验证通过：`openspec validate review-ab56d580 --strict`、`go build ./...`、`go vet ./...`、`go test ./...`、`go test -race ./...`。端到端共 147 项通过：真实 OpenSSH 32、TLS 代理 24、OAuth client credentials 28、真实 PostgreSQL 15、Redis/MySQL/MongoDB 33、中心 15。
