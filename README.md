# KeyKoi

**English** · [简体中文](README.zh-CN.md)

![A hand-drawn koi guards a credential vault connected to a terminal, Git, and databases.](docs/assets/keykoi-intro.webp)

**Keep service credentials in an encrypted vault on your Mac and let familiar tools use them on demand.** KeyKoi is for developers who use Git, SSH, cloud CLIs, database clients, and agents on the same machine. Manage credentials, grants, and usage records from the CLI or local console.

[Quick start](#quick-start) · [Set up with your agent](docs/agent-setup.md) · [User guides (中文)](docs/索引/使用指南.md) · [Test results (中文)](docs/验收/验收总览.md) · [MIT](LICENSE)

## Copy this to let your agent set up KeyKoi

Send the following prompt to an agent that can operate your Mac's terminal. [Read the full agent setup guide](docs/agent-setup.md).

```text
Help me set up KeyKoi on this Mac. Read the setup guide first:
https://github.com/SJF-ECNU/KeyKoi/blob/main/docs/agent-setup.md

Check my existing installation, credentials, and tool configuration. Connect
the Git, cloud CLI, SSH, database, and script workflows I actually use, keeping
my usual commands wherever possible. Back up any configuration you plan to
change. Let me enter passwords, private-key passphrases, or API keys directly
in my terminal without echoing them. Verify each workflow and tell me what
works, what still needs my input, and how to roll back.
```

## How KeyKoi works

Import a credential, then create a **binding** that identifies the destination. Add a **grant** for the user or agent that needs it. The grant controls how the credential can be used and when identity verification is required. The local KeyKoi service enforces the grant and records the outcome.

| Mode | What the tool gets | Typical uses |
| --- | --- | --- |
| Proxy (`proxy`) | The response from a request KeyKoi authenticates upstream | HTTP, PostgreSQL, Redis, MySQL, MongoDB |
| Signing (`sign`) | A signature generated inside KeyKoi | SSH agent and supported cloud request signing |
| Runtime delivery (`runtime_delivery`) | Selected credential fields injected into a child process | GitHub CLI, Alibaba Cloud CLI, and tools with native authentication |

## Quick start

KeyKoi is primarily tested on **macOS arm64**. Building from source requires **Go 1.26.11 or later**. These steps start with a master password. You can set up Touch ID later.

```bash
git clone https://github.com/SJF-ECNU/KeyKoi.git
cd KeyKoi
KEYKOI_BIOMETRIC_APP=0 KEYKOI_SKIP_BIOMETRIC=1 bash packaging/macos/install.sh
export PATH="$HOME/Library/Application Support/KeyKoi/bin:$PATH"

keykoi init
keykoi status
keykoi ui
```

The installer registers the local background service. On first use, `keykoi init` prompts for a master password. For an existing vault or after a service restart, run `keykoi unlock`. The console listens on `127.0.0.1:8378` by default.

### Try runtime delivery

Run this example in your own terminal with Python 3 available. Enter a dummy value at the first prompt. The grant applies to your local account and limits delivery to the `token` field.

```bash
CREDENTIAL_ID="$(keykoi --json credential add --kind api_key --label 'Demo credential' --field token)"
keykoi binding add --id demo --route demo --credential "$CREDENTIAL_ID" \
  --origin https://example.com --scheme bearer --runtime-field token
GRANT_ID="$(keykoi --json grant add --principal me --binding demo \
  --mode runtime_delivery --auth once | python3 -c 'import json, sys; print(json.load(sys.stdin)["id"])')"
keykoi auth verify --method password --grant "$GRANT_ID" --mode runtime_delivery

keykoi run --binding demo --exe /bin/sh --env DEMO_TOKEN=field:token -- \
  -c 'test -n "$DEMO_TOKEN" && printf "%s\n" "Demo credential delivered"'
keykoi grant revoke --id "$GRANT_ID"
```

The example checks delivery locally and prints only the outcome. For everyday use, keep using `keykoi run` or set up a command shim to retain the original command. [Tool setup and troubleshooting (中文)](docs/指南/工具接入与排障.md)

## Security and recovery

- **Storage and unlock.** KeyKoi encrypts credentials before writing them to the database. Unlock with a master password or set up the signed helper for Touch ID. Keep the master password for vault recovery. [Touch ID setup and renewal (中文)](docs/指南/生物识别助手续签与部署.md)
- **Grants and revocation.** Grants apply to a principal, binding, and usage mode. Locking the vault or revoking a grant stops further use through KeyKoi. Rotate or revoke any credential already delivered to a child process at the upstream service. Use runtime delivery with trusted programs.
- **Local boundary.** KeyKoi checks registered principals and grants. Processes running under the same macOS account still share the OS account's permissions.
- **Backup and restore.** Use `keykoi backup --out PATH` to save an encrypted backup. A restored vault starts locked, and prior grants must be reviewed before use. Keep your master password and backup available before upgrading or moving to another Mac.

## Project status and development

The local vault, console, Git and SSH workflows, cloud CLIs, and database proxies have macOS acceptance coverage. Coverage varies by protocol and tool version. Linux file isolation, Windows, and multi-host deployments still need full validation.

```bash
go build ./...
go vet ./...
go test ./...
```

[Project docs (中文)](docs/首页.md) · [Implementation design (中文)](KeyKoi_Implementation_Plan_v0.1.md) · [Report an issue](https://github.com/SJF-ECNU/KeyKoi/issues)

## License

KeyKoi is available under the [MIT License](LICENSE). Third-party dependencies retain their respective licenses.
