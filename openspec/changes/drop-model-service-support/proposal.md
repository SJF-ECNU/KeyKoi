## Why

缩小 KeyKoi 的产品范围，移除模型服务 API Key 专用支持和验收依赖。

## What Changes

- 移除模型专用会话入口和测试夹具。
- 停止推荐模型 API 接入，保留通用业务凭证能力。

## Capabilities

### New Capabilities

- `credential-scope`: 界定项目维护的凭证场景。

## Impact

HTTP 网关、控制台文案、测试和使用文档。
