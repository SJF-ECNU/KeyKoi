---
type: guide
status: current
updated_at: 2026-11-21
---

# Set up KeyKoi with your agent

**English** · [简体中文](指南/Agent部署与凭证导入.md)

Share this file with an agent that can operate your Mac's terminal. Tell it which tools you use and how you normally invoke them. For example:

> Set up KeyKoi on this Mac and connect the Git, GitHub CLI, cloud CLI, SSH, and database workflows I use. Keep my usual commands and configuration wherever possible. Let me enter secrets in my terminal and approve Touch ID prompts. Report what you verified for each tool and what still needs my input.

## Start with the user's existing workflows

1. **Inventory the tools.** Check versions, normal commands, credential sources, destinations, and configuration scope. Treat each Git repository, AWS profile, SSH host, and database connection as its own integration. Start with the workflows the user uses most.
2. **Identify the caller and choose an access mode.** Run `keykoi whoami` from the environment that will use the credential. Grant access to the intended local account or agent. Prefer the tool's native integration and grant only the fields it needs.
3. **Back up before making changes.** Reuse the existing vault. Run `keykoi backup --out "$BACKUP_DIR/vault.encrypted.json"` for an encrypted snapshot, then back up the configuration you will modify. Use a private directory with permissions set to `0700`. Protect any backup that contains existing secrets.
4. **Keep secret input local.** Have the user enter master passwords, key passphrases, and API keys in the terminal without echo. Use `--field-file` to read an existing protected file. Keep administrator and intermediary tokens out of chat, arguments, shell history, logs, and screenshots. Turn off shell tracing. Preserve the original credentials for rollback.

## Deploy KeyKoi and import credentials

For an existing installation, locate the installed binary and data directory, then check `keykoi status`. If the vault is locked, open a local terminal and let the user run `keykoi unlock`. Keep an existing signed biometric helper in place.

For a fresh installation, check the macOS and Go requirements first. Have the user run the initialization command in their terminal. [Requirements and quick start](../README.md#quick-start)

```bash
git clone https://github.com/SJF-ECNU/KeyKoi.git
cd KeyKoi
KEYKOI_SKIP_BIOMETRIC=1 KEYKOI_BIOMETRIC_APP=0 bash packaging/macos/install.sh
export PATH="$HOME/Library/Application Support/KeyKoi/bin:$PATH"
keykoi init
keykoi status
keykoi ui
```

Import a credential through the console or CLI, create a binding for its destination, and grant access to the intended caller. For a generic service API key, use `keykoi credential add --kind api_key --label 'Service name' --field token` and let the user enter the token without echo. Use the repeatable `--runtime-field` option when the binding needs a field allowlist for runtime delivery. [Console and grants (中文)](指南/使用看板与授权.md) · [Optional Touch ID setup (中文)](指南/生物识别助手续签与部署.md)

## Connect the tools the user already uses

| Current workflow | How to connect it | What the user runs afterward |
| --- | --- | --- |
| Git over HTTPS | Create a Basic-auth gateway binding and use `keykoi git setup` to configure URL rewriting and a credential helper for the intended host | The same Git commands and repository URLs |
| GitHub CLI | Register a shim pointing to the real `gh` executable and deliver `GH_TOKEN` at runtime | The same `gh` commands in shells that resolve the shim first |
| AWS CLI | Use the `aws-cli-helper` adapter to configure the profile's `credential_process` | AWS CLI commands with the configured profile |
| Alibaba Cloud CLI | Register a shim and deliver AccessKey fields and an optional STS token, with a separate CLI config path | The same `aliyun` service commands |
| SSH | Run a KeyKoi SSH agent for the binding and set the identity and agent in the existing host block | The same `ssh host` command |
| Database client | Use `keykoi db-proxy` for PostgreSQL, Redis, MySQL, or MongoDB | The same client configured for the local proxy, using an intermediary session token |
| Scripts, service HTTP, and other CLIs | Use the HTTP gateway where possible. Use `keykoi run` with selected fields when the tool needs the original values. Install a persistent shim after checking compatibility | The same business logic, with an adjusted authentication entry point or launch command |

### Git, cloud CLIs, and other commands

- **Git HTTPS.** Check the repository and its existing credential helper, then back up the configuration. Use `keykoi git setup --host HOST --binding BINDING --route ROUTE --gateway GATEWAY --file CONFIG_FILE` at the intended scope. Get the gateway address from `keykoi status`. Use `git ls-remote` for an authorized read-only check and `keykoi git teardown` for rollback. For Git over SSH, follow the SSH steps below.
- **GitHub CLI and command shims.** Check `keykoi shim list` before taking an executable path from PATH. For GitHub CLI, use `keykoi shim install --name gh --exe "$REAL_GH" --binding "$BINDING" --env GH_TOKEN=field:token` with a runtime-delivery grant that covers the token field. Use `gh api user --silent` to check authentication through the shim. Update PATH when the user wants the original command to resolve to the shim, then verify the path in a new shell.
- **AWS CLI.** Check the installed version and path, then prepare the binding and grant described by the adapter. Run `keykoi integration plan --profile aws-cli-helper` to preview the profile update, followed by `keykoi integration attach --profile aws-cli-helper` and `keykoi integration verify --profile aws-cli-helper` when the preview matches the intended setup. If the version or path differs from the adapter, use an integration suitable for that installation. [AWS adapter](../adapters/aws-cli-helper.yaml)
- **Alibaba Cloud CLI.** Register the real executable and use a dedicated `--config-path` for managed calls so the original configuration remains available. Map the session token field when using STS. [Alibaba Cloud setup and configuration drift (中文)](指南/工具接入与排障.md)

### SSH and PEM files

Check the existing SSH host blocks and the files the user selected. Separate SSH keys from certificates, service TLS keys, and fixtures. Deduplicate by public key fingerprint when available. KeyKoi supports traditional RSA and EC PEM, unencrypted PKCS#8, and OpenSSH. An encrypted PKCS#8 file marked `BEGIN ENCRYPTED PRIVATE KEY` needs format conversion before import. For a supported password-protected key, add `--field private_key_passphrase` and let the user enter the passphrase without echo.

```bash
CRED_ID="$(keykoi --json credential add --kind ssh_key --label 'Example server' \
  --field-file "private_key=$HOME/.ssh/server.pem")"
BINDING_ID=ssh-demo
keykoi binding add --id "$BINDING_ID" --route "$BINDING_ID" \
  --credential "$CRED_ID" --origin ssh://server.example.com
keykoi grant add --principal me --binding "$BINDING_ID" --mode sign --auth once
DATA_DIR="$HOME/Library/Application Support/KeyKoi/data"
keykoi --data-dir "$DATA_DIR" ssh-agent --binding "$BINDING_ID" \
  --agent-socket "$DATA_DIR/ssh-demo.sock"
```

Each KeyKoi SSH agent serves one binding. Use separate sockets for distinct keys. For persistent use, check for an existing agent and register a uniquely named LaunchAgent for the current macOS user. In a second terminal, set `SSH_AUTH_SOCK` to the intended socket for `ssh-add -L` and match the public key to the original. Use `ssh-keygen -Y sign` and verify the signature over a temporary local message. If required, have the user run `keykoi auth verify --method password --grant GRANT_ID --mode sign` or respond to Touch ID.

Once local verification passes, set the public key and dedicated agent in the existing host block. Preserve the hostname, user, port, jump host, and host-key settings. Use `ssh -G HOST` to check the effective configuration. Keys without a known host mapping can be imported and verified without editing any host block.

```sshconfig
Host example-host
  HostName server.example.com
  IdentityFile ~/.ssh/keykoi/ssh-demo.pub
  IdentityAgent "/Users/example/Library/Application Support/KeyKoi/data/ssh-demo.sock"
  IdentitiesOnly yes
```

### Databases, HTTP, signing, and OAuth

- **Databases.** Import the account credential, add a binding for the protocol, and grant `proxy`. Start the loopback listener with `keykoi db-proxy --protocol PROTOCOL --binding ID --listen 127.0.0.1:PORT`. Choose `postgres`, `redis`, `mysql`, or `mongo`. Keep upstream TLS verification and add a private CA with `--upstream-ca` when required. Pass the intermediary token locally to the client and keep it out of logs and arguments. Verify with a read-only query. [Database and proxy tests (中文)](验收/验收总览.md)
- **HTTP.** Register the allowed target and paths for Bearer, API key, or Basic authentication. Launch a script with `keykoi run --mode proxy --route ROUTE --exe ABSOLUTE_PATH`. Use `--env NAME=runtime:gateway_base` and `--env NAME=runtime:session_token` to supply the local gateway and session. Consider `tls-proxy` when a client needs to keep the upstream HTTPS address. Verify protocol support, certificate trust scope, and client configuration first.
- **Signing and OAuth.** When a service supports a signature or token exchange, use the matching KeyKoi integration. Choose the protocol and settings covered by acceptance tests. Verify with an authorized read-only request and retain the upstream service's own permissions and rotation rules. [Signing and OAuth tests (中文)](验收/验收总览.md)

## Verify and hand off

Compare the resulting workflow with the user's original command and configuration. Prefer local signing, a controlled service, or an authorized read-only request. Connect to a real SSH host only if the user has authorized remote login verification.

Report each tool's status separately. State whether you imported the credential, configured the integration, and verified the original command. Call out any address change, profile selection, or Touch ID prompt. Give the backup location and the appropriate rollback step, such as `shim remove`, `integration detach`, `git teardown`, or restoring an SSH host block and stopping its new agent. Merge the rollback with any changes the user has made since setup.
