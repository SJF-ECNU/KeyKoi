---
type: guide
status: current
updated_at: 2026-11-21
---

# 让 Agent 帮你把常用工具接入 KeyKoi

[English](../agent-setup.md) · **简体中文**

把本文件交给能操作你本机终端的 Agent，再告诉它你平时用哪些工具、怎样调用。例如：

> 请在这台 Mac 上部署 KeyKoi，把我现有的 Git、GitHub CLI、云 CLI、SSH 和数据库客户端按实际用途接好。尽量保留原命令和配置习惯。需要输入密码或按指纹时打开本机终端，逐个告诉我哪些工具已验证、哪些还有一步。

## 先盘点用户的工作方式

1. **弄清用户每天怎么用**。记录工具及版本、当前调用命令、凭证来源、目标和配置范围。把某个 Git 仓库、AWS profile、SSH 主机和数据库连接分别作为接入对象。先处理用户经常用的路径。
2. **明确调用主体和用钥方式**。在实际执行环境中用 `keykoi whoami` 核实主体，按账户或目标 Agent 授权。选该工具原生支持的接入方式，只使用需要的字段，并逐项验证。
3. **先备份再接入**。复用现有保险库，用 `keykoi backup --out "$BACKUP_DIR/vault.encrypted.json"` 保存加密副本。备份要修改的配置，目录权限设为 `0700`。如果配置原本含秘密，把其备份也按秘密处理。
4. **让秘密走本机**。主密码、私钥口令和 API Key 都由用户在终端隐藏输入，或用 `--field-file` 从已有的受保护文件读取。管理令牌和中介会话令牌也当作秘密。关闭 shell 跟踪，避免凭证出现在聊天、命令参数、历史、日志或截图里。原凭证文件保留作回退。

## 部署和导入

已安装时先定位实际二进制和数据目录，用 `keykoi status` 确认后台和锁定状态。需要解锁时打开终端运行 `keykoi unlock`。已有的签名助手继续沿用。

首次安装按 README 的 macOS 和 Go 要求执行。初始化命令请在用户自己的终端运行。[安装要求与快速开始](../../README.zh-CN.md#快速开始)

```bash
git clone https://github.com/SJF-ECNU/KeyKoi.git
cd KeyKoi
KEYKOI_SKIP_BIOMETRIC=1 KEYKOI_BIOMETRIC_APP=0 bash packaging/macos/install.sh
export PATH="$HOME/Library/Application Support/KeyKoi/bin:$PATH"
keykoi init
keykoi status
keykoi ui
```

用控制台或 CLI 导入凭证，再创建指向实际目标的绑定，并给使用者设置授权。普通业务 API Key 可用 `keykoi credential add --kind api_key --label '业务服务' --field token` 隐藏输入。有现成的模式就直接用；需要指定运行时交付范围时，用可重复的 `--runtime-field` 逐个允许字段。可选 Touch ID 按签名助手指南配置。[控制台与授权](使用看板与授权.md) · [Touch ID 部署与续签](生物识别助手续签与部署.md)

## 按工具保留日常入口

| 用户原来的用法 | 接入方式 | 用户之后怎么用 |
| --- | --- | --- |
| `git clone`、`git fetch` 走 HTTPS | 为目标建立 Basic 网关绑定，使用 `keykoi git setup` 设置目标主机的 URL 重写和凭证助手 | 保留原仓库地址和 Git 命令 |
| `gh` | 用真实 `gh` 的绝对路径安装命令代理，按需交付 `GH_TOKEN` | 在 PATH 使用代理的终端继续运行 `gh` |
| AWS CLI | 用 `aws-cli-helper` 适配器为选定 profile 设置 `credential_process` | 使用接入的 AWS profile，其他 profile 维持自己的认证方式 |
| 阿里云 CLI | 安装命令代理，给真实 CLI 交付 AccessKey 和可选 STS 令牌，并指定隔离配置路径 | 继续运行常用 `aliyun` 业务命令 |
| `ssh 主机名` | 用对应绑定启动 KeyKoi SSH Agent，在现有主机段指定公钥和 Agent | 保留原主机名、端口和跳板设置 |
| 数据库客户端 | 用 `keykoi db-proxy` 为 PostgreSQL、Redis、MySQL 或 MongoDB 建立本机连接入口 | 用现有客户端连接本机代理，按协议提供中介会话令牌 |
| 脚本、业务 HTTP 或其他 CLI | HTTP 优先走 KeyKoi 网关。工具需要原始值时，用 `keykoi run` 仅交付所需字段。有确认过的兼容性再做长期命令代理 | 保留业务逻辑，调整认证入口或单次启动方式 |

### Git、云 CLI 和常用命令

- **Git HTTPS**。先核对目标仓库和现有凭证助手，只在需要的 Git 配置范围执行 `keykoi git setup --host HOST --binding BINDING --route ROUTE --gateway GATEWAY --file CONFIG_FILE`。网关地址从 `keykoi status` 取得。备份被改的配置。用 `git ls-remote` 做只读验收；需要回退时用对应的 `keykoi git teardown`。Git 走 SSH 时使用下面的 SSH 步骤。
- **GitHub CLI 和通用命令代理**。先用 `keykoi shim list` 核对是否已接入，避免把自己登记为原命令。GitHub CLI 的示例为 `keykoi shim install --name gh --exe "$REAL_GH" --binding "$BINDING" --env GH_TOKEN=field:token`，其中绑定里需要有 `token` 字段和运行时交付授权。用 `gh api user --silent` 确认认证经过本次接入。用户需要原命令自动命中时再更新 PATH，并验证新终端实际命中的路径。
- **AWS CLI**。先确认本机安装方式和工具版本，按适配声明准备绑定和授权。执行 `keykoi integration plan --profile aws-cli-helper` 查看将修改的 profile，通过后再运行 `keykoi integration attach --profile aws-cli-helper` 和 `keykoi integration verify --profile aws-cli-helper`。若真实版本或路径与声明不匹配，按实际安装调整接入方案。[AWS 适配声明](../../adapters/aws-cli-helper.yaml)
- **阿里云 CLI**。从原始 CLI 路径接入。为管理调用单独指定 `--config-path`，保留原有配置文件。使用 STS 时对应增加会话令牌字段。[阿里云接入命令和配置漂移处理](工具接入与排障.md)

### SSH 与 PEM

先核对 `~/.ssh/config` 和用户指定的 PEM。根据用途排除证书、项目 TLS 私钥和验收夹具。能取得公钥时按指纹去重。支持传统 RSA 和 EC PEM、未加密 PKCS#8 和 OpenSSH 格式。加密 PKCS#8（`BEGIN ENCRYPTED PRIVATE KEY`）需要先处理格式。带口令的传统 PEM 或 OpenSSH 私钥在导入时加 `--field private_key_passphrase`，由用户在本机终端隐藏输入。

```bash
CRED_ID="$(keykoi --json credential add --kind ssh_key --label '示例服务器' \
  --field-file "private_key=$HOME/.ssh/server.pem")"
BINDING_ID=ssh-demo
keykoi binding add --id "$BINDING_ID" --route "$BINDING_ID" \
  --credential "$CRED_ID" --origin ssh://server.example.com
keykoi grant add --principal me --binding "$BINDING_ID" --mode sign --auth once
DATA_DIR="$HOME/Library/Application Support/KeyKoi/data"
keykoi --data-dir "$DATA_DIR" ssh-agent --binding "$BINDING_ID" \
  --agent-socket "$DATA_DIR/ssh-demo.sock"
```

每个 KeyKoi SSH Agent 服务一个绑定。为不同私钥使用不同套接字；长期使用时可用当前用户的 LaunchAgent 保持运行，先核对已有 Agent，再用唯一标签注册。先在另一个终端用对应的 `SSH_AUTH_SOCK` 和 `ssh-add -L` 枚举公钥，与原公钥核对。再用 `ssh-keygen -Y sign` 对临时消息签名并验签。需要预验证时，在本机终端执行 `keykoi auth verify --method password --grant <授权ID> --mode sign`，或按 Touch ID 提示确认。

通过后，在现有主机段把 `IdentityFile` 换成对应公钥，并指定专属 Agent。用 `ssh -G 主机名` 核对生效值。没有明确主机映射的钥匙可先导入并验签。以下为目标配置示例：

```sshconfig
Host example-host
  HostName server.example.com
  IdentityFile ~/.ssh/keykoi/ssh-demo.pub
  IdentityAgent "/Users/example/Library/Application Support/KeyKoi/data/ssh-demo.sock"
  IdentitiesOnly yes
```

### 数据库、HTTP 与签名接口

- **数据库**。导入账号凭证，选择对应协议绑定并授予 `proxy`。用 `keykoi db-proxy --protocol postgres|redis|mysql|mongo --binding ID --listen 127.0.0.1:PORT` 配置对应的本机入口，命令中只填一个协议。保留上游 TLS 校验，私有 CA 使用 `--upstream-ca`。把代理返回的中介令牌仅在本机交给客户端，避开日志和命令行参数。用原客户端执行只读查询，验证后再长期接入。[数据库与代理验收](../验收/验收总览.md)
- **HTTP**。对 Bearer、API Key 或 Basic 服务登记允许的目标和路径，通过网关交付认证。以 `keykoi run --mode proxy --route ROUTE --exe ABSOLUTE_PATH` 启动脚本时，可用 `--env NAME=runtime:gateway_base` 与 `--env NAME=runtime:session_token` 将访问本机网关所需的信息交给脚本。确实需要保留原 HTTPS 地址的客户端再评估 `tls-proxy`，先验证协议、证书信任范围和客户端设置。
- **签名与 OAuth**。工具支持签名结果或令牌交换时，优先用现有签名器或 OAuth 路径。按实际服务选择已验收的协议和参数，使用只读请求验证，保留上游服务的授权与轮换规则。[协议签名和 OAuth 验收](../验收/验收总览.md)

## 验收与交接

逐项对照用户原来的工作方式，确认原命令、配置范围、接入方式和触发验证时的体验。优先用本地签名、受控服务端或获准的只读请求验收。只在用户授权验证远端登录时访问真实 SSH 目标。

交接时按工具报告 **已导入、已接入、已用原命令验证** 的实际结果，说明哪些入口需要改地址、选 profile 或触发 Touch ID。标明备份所在目录。回退按接入方式做局部操作，例如 `shim remove`、`integration detach`、`git teardown`，或还原 SSH 主机段、停用本次新增的 Agent 并撤销授权。用户后续修改过配置时，按字段合并回退。
