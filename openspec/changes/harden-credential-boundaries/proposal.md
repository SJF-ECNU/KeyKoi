## Why

全量测试发现 Go 运行时与 SSH 依赖需要更新，普通本机主体可按对象 ID 操作任意会话与许可，MongoDB 上游也缺少传输保护。

## What Changes

- 更新 Go 工具链最低版本和 x/crypto，扫描程序的调用路径。
- 限制 IPC 清理和完整审计的访问范围。
- 默认要求 MongoDB 上游通过证书校验。

## Capabilities

### New Capabilities

- `local-credential-boundaries` 约束本机 IPC 控制和 MongoDB 上游传输。

## Impact

涉及 Go 构建、守护进程、Broker 和 MongoDB 代理。使用明文 MongoDB 的开发环境需要显式指定 `--upstream-insecure`。
