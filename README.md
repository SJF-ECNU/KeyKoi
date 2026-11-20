# 钥鲤 KeyKoi

![手绘锦鲤守着凭证保险库，经授权后连接终端、Git 和数据库工具。](docs/assets/keykoi-intro.webp)

**把业务凭证收进本机加密保险库，让熟悉的工具按需使用。** KeyKoi 面向在同一台 Mac 上使用 Git、SSH、云 CLI、数据库客户端和 Agent 的开发者。你可以用命令行或本机控制台管理凭证、授权和使用记录。

[快速开始](#快速开始) · [交给 Agent 部署与导入](docs/指南/Agent部署与凭证导入.md) · [使用指南](docs/索引/使用指南.md) · [验收记录](docs/验收/验收总览.md) · [MIT](LICENSE)

## 复制这段，让你的 Agent 帮你部署

把下面这段发给能操作你本机终端的 Agent。也可以先看看[完整接入引导](docs/指南/Agent部署与凭证导入.md)。

```text
请帮我在这台 Mac 上部署 KeyKoi。先读取 https://github.com/SJF-ECNU/KeyKoi
中的 docs/指南/Agent部署与凭证导入.md，检查本机已有的安装、凭证和工具配置。

按我实际使用的 Git、云 CLI、SSH、数据库或业务脚本逐项接入，尽量保留原来的命令。
请先做可回退的备份。需要密码、私钥口令或 API Key 时，让我在本机终端隐藏输入。
逐项验证后告诉我哪些工具已经可以照常使用、哪些还需要现场确认，以及怎么回退。
```

## KeyKoi 怎么工作

导入凭证后，新建一个**绑定**，指定凭证用于哪个目标服务。再为某个用户或 Agent 设置**授权**，决定它可以怎样使用这个绑定，以及每次使用前是否需要验证。KeyKoi 后台执行授权并记录结果。

| 用钥方式 | 工具收到什么 | 常见场景 |
| --- | --- | --- |
| 代理 `proxy` | 请求结果。KeyKoi 向上游认证 | HTTP、PostgreSQL、Redis、MySQL、MongoDB |
| 签名 `sign` | 签名结果。私钥留在 KeyKoi 的执行路径 | SSH Agent、已适配的云请求签名 |
| 运行时交付 `runtime_delivery` | 明确允许的凭证字段，由 KeyKoi 注入子进程 | GitHub CLI、阿里云 CLI 等依赖原生认证方式的工具 |

## 快速开始

当前主要在 **macOS arm64** 上验收。从源码安装需要 **Go 1.26.11 或更新版本**。这套命令使用主密码启动，Touch ID 可以之后配置。

```bash
git clone https://github.com/SJF-ECNU/KeyKoi.git
cd KeyKoi
KEYKOI_BIOMETRIC_APP=0 KEYKOI_SKIP_BIOMETRIC=1 bash packaging/macos/install.sh
export PATH="$HOME/Library/Application Support/KeyKoi/bin:$PATH"

keykoi init
keykoi status
keykoi ui
```

安装脚本注册本机后台服务。首次运行 `keykoi init` 时，终端会提示输入主密码。已有保险库或服务重启后，用 `keykoi unlock` 解锁。控制台默认监听 `127.0.0.1:8378`。

### 试一次凭证交付

在自己的终端运行以下示例（需 Python 3）。第一条命令会隐藏输入，填入任意测试值即可。示例只为当前账户授权，且只允许交付 `token` 字段。

```bash
CREDENTIAL_ID="$(keykoi --json credential add --kind api_key --label '试用凭证' --field token)"
keykoi binding add --id demo --route demo --credential "$CREDENTIAL_ID" \
  --origin https://example.com --scheme bearer --runtime-field token
GRANT_ID="$(keykoi --json grant add --principal me --binding demo \
  --mode runtime_delivery --auth once | python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])')"
keykoi auth verify --method password --grant "$GRANT_ID" --mode runtime_delivery

keykoi run --binding demo --exe /bin/sh --env DEMO_TOKEN=field:token -- \
  -c 'test -n "$DEMO_TOKEN" && printf "%s\n" "测试凭证已交付"'
keykoi grant revoke --id "$GRANT_ID"
```

这个示例只检查测试凭证是否成功交付，无需访问网络或打印凭证。接入实际工具时可继续使用 `keykoi run`，也可按工具指南建立命令代理，保留原来的日常命令。[工具接入与排障](docs/指南/工具接入与排障.md)

## 安全与恢复

- **存储与解锁**。凭证写入数据库前加密。解锁支持主密码，以及配置签名助手后的 Touch ID。主密码是保险库恢复所需的凭据。[Touch ID 部署与续签](docs/指南/生物识别助手续签与部署.md)
- **授权与撤销**。授权按主体、绑定和用钥方式设置。锁库或撤销权限会停止后续用钥。运行时已经交给子进程的凭证仍需按上游规则撤销或轮换，目标程序必须可信。
- **本机边界**。KeyKoi 能区分已登记的调用主体和授权路径。同一 macOS 账户下的进程仍共享系统用户权限。
- **备份恢复**。`keykoi backup --out <文件>` 生成加密备份。恢复后保险库保持锁定，旧授权需要重新确认。换机或升级前同时保存主密码和备份。

## 项目状态与开发

macOS 的单机保险库、控制台、Git/SSH、云 CLI 和数据库代理具备验收记录。测试覆盖范围随协议和工具版本而异。Linux 文件隔离、Windows 和多设备跨主机部署仍待完整验收。

```bash
go build ./...
go vet ./...
go test ./...
```

[项目文档](docs/首页.md) · [实施设计](KeyKoi_Implementation_Plan_v0.1.md) · [报告问题](https://github.com/SJF-ECNU/KeyKoi/issues)

## 开源协议

KeyKoi 使用 [MIT License](LICENSE)。第三方依赖保留各自的许可证。
