---
workstream: drop-model-service-support
---

# 移除模型服务 API Key 专用支持

模型服务 API Key 退出产品支持范围。删除网关将 Google 模型客户端头作为会话入口的特例，保留出站保护。修剪 SDK 测试和夹具，以本地通用业务服务验证 Bearer、自定义 Key 头、Basic 和代理启动器，并保留 Git helper 验收。历史记录保留原位置。通用凭证没有可信的服务用途分类，本次不新增域名名单或密钥格式猜测。

见 [执行清单](tasks.md)。
