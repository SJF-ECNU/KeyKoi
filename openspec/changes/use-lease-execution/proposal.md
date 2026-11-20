## Why

独立代理的授权应覆盖实际执行，代理请求应保留调用者的会话身份。

## What Changes

- 让数据库代理用同一次授权执行直到连接结束或被撤销。
- 统一许可复核与期限处理，分开 TLS 代理执行和材料交付。

## Capabilities

### New Capabilities

- `leased-execution`: 代理使用对应调用会话与有界的执行许可。

## Impact

影响 Broker、daemon、IPC 和代理适配器。
