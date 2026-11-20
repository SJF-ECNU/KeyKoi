---
type: worklog
project: KeyKoi
workstream: biometric-unlock-and-auth-policy
status: completed
recorded_at: 2026-11-20T01:31:00+08:00
started_at: unknown
completed_at: 2026-11-20T01:31:00+08:00
timezone: Asia/Shanghai
agent: biometric-renewal
client: DeepSeek Harness
model: unknown
session_id: unknown
branch: unavailable
commit: null
---

# 生物识别助手部署与描述文件 7 天续签自动化

## 任务计划书

[[project-memory/任务计划/生物识别解锁与授权策略|任务计划书 · 生物识别解锁与授权策略]] 新增的「部署与描述文件续签」步骤表；工作流 [[project-memory/工作流/生物识别解锁与授权策略|生物识别解锁与授权策略]] 同步当前状态与下一步。

目标：解决 `.app` 内 `embedded.provisionprofile` 7 天过期导致助手无法启动的问题，并把 `.app` 的部署自动化；不改 Go 业务代码，不改其他 acceptance 与 openspec。

## 结果、改动与验证

**续签机制（三层）。** ① `packaging/macos/install-biometric-app.sh` 用 `security cms -D -i <app>/Contents/embedded.provisionprofile | plutil -extract ExpirationDate raw -o - -` 读出到期时间，换算剩余秒/天，剩余 <2 天（`KEYKOI_BIOMETRIC_RENEW_DAYS` 可调）或描述文件缺失/读不出时才调 `build-biometric-app.sh --derived-data … --no-probe` 重建（`xcodebuild -allowProvisioningUpdates` 负责向 Apple 重新签发），随后 `ditto` 到 `<prefix>/KeyKoi Biometric.app` 的临时目录、先在临时目录复校 `codesign --verify --strict` 与 `keychain-access-groups`、再整体替换，失败不留下半成品。`--status` 打印 `profile_expiry` / `remaining_days` / `signature_team` 等 key=value（stderr 同步人读摘要），`--deploy-only` 只部署已有 DerivedData 产物，`--force-expiry-check` 供验收模拟临期。脚本只在「构建 → 复制 → 校验 → 报告」这条链上工作，不调用助手 `store/load/delete`，不写、不改、不删任何 Keychain 条目（验收用 grep 断言）。② `packaging/macos/install-biometric-renew.sh` 用 `python3 plistlib` 生成并 `bootstrap` LaunchAgent `com.keykoi.biometric-renew`，`StartCalendarInterval` 每周一次（默认周日 03:17，可 `--weekday/--hour/--minute` 覆盖），`StandardOutPath`/`StandardErrorPath` 都是 `<prefix>/data/biometric-renew.log`；`--status`（含按 plist 自算的 `next_fire`）、`--run-now`（kickstart 后等 `install_biometric_app=` 收尾标记，最多 600s）、`--uninstall`（bootout + 删 plist，保留日志）、`--plist-dir`（验收用临时目录）。③ `packaging/macos/install.sh` 默认调 `--deploy-only` 部署 `.app`（`KEYKOI_BIOMETRIC_APP=0` 关闭），成功时把 `EnvironmentVariables.KEYKOI_BIOMETRIC_HELPER=<prefix>/KeyKoi Biometric.app/Contents/MacOS/keykoi-biometric` 写进 keykoid 的 plist，失败只打印 `note:` 与重建命令、不中断安装。

**launchd 环境下的自动签名。** launchd 不加载 shell 启动文件，`xcodebuild` 自动签名要读真实 `HOME` 下的登录钥匙串（Apple Development 身份）和 Xcode 账户缓存，因此 plist 的 `EnvironmentVariables` 显式写 `HOME=/Users/shjf`、`PATH`（含 `/Applications/Xcode.app/Contents/Developer/usr/bin`）、`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`、`KEYKOI_DEV_TEAM`、`KEYKOI_PREFIX`；`install-biometric-app.sh` 自身在 `HOME` 缺失时用 `dscl` 反查、`DEVELOPER_DIR` 缺失时用 `xcode-select -p` 兜底，并用 `--no-probe` 跳过 GUI 探针（launchd 里 `available` 会返回 unavailable，续签只依赖签名/权限/描述文件三项）。实测：`env -i` 空环境跑 `--build-if-needed --force-expiry-check` 退出 0；`launchctl kickstart` 后日志出现 `build_exit=0` 与 `deployed_app=<prefix>/KeyKoi Biometric.app`，即 launchd 里真的完成了自动签名重建。对比实验：把 plist 的 `HOME` 指到临时目录时构建失败并落到 `failure_class=apple-id`（`No Accounts` / 无 `Mac Development` 证书），说明这个环境变量是有效载荷而不是装饰。

**实际到期时间与调度。** 本机 `.app` 的描述文件 `ExpirationDate = 2026-11-26T17:13:46Z`（epoch 1795713226，UUID `c482a923-4ff6-4ec8-adca-5e08180744e5`），`--status` 报 `remaining_days=7.0`、`signature_team=977QNJU6V6`、`codesign_verify=ok`、`entitlements_keychain_access_groups=yes`。真实 LaunchAgent 已加载：`com.keykoi.biometric-renew`，`next fire = 2026-11-22 03:17`（早于到期 4 天），`launchctl print` 里环境变量与上面一致；`--run-now` 在真实 prefix 跑通并写入 `<prefix>/data/biometric-renew.log`。

**验收。** 新增 `tests/acceptance/biometric-renewal.sh`：空 prefix 首次构建部署、`--status` 的到期时间/剩余天数/签名团队、新鲜时跳过构建、`--force-expiry-check` 触发重建、删掉 `embedded.provisionprofile` 后 `--status` 退出 2 且 `--build-if-needed` 重新签发、`codesign` 与 `keychain-access-groups` 复校、构建失败（`PATH` 之外的 `KEYKOI_BIOMETRIC_BUILD_SCRIPT` 替身，退出码 3）给出 `manual:` 且不破坏已部署 `.app`、`install.sh` 的 plist（`plutil -lint` + `KEYKOI_BIOMETRIC_HELPER` 指向 app 内助手 + `KEYKOI_BIOMETRIC_APP=0` 分支）、LaunchAgent plist 语义（`StartCalendarInterval` / `EnvironmentVariables` / 日志路径）与 `plutil -lint`、`--run-now` 在 launchd 里构建+部署成功、`--uninstall` 清理、脚本不含 `store/load/delete`。结果 **86/86，exit 0**，写 `docs/验收/artifacts/biometric-renewal/result.json`。全程用临时 prefix、临时 HOME（install.sh 的 LaunchAgents 目录）与带 PID 后缀的一次性标签，不等待一周。

**修掉的三个实现问题（记录以便复现）。** ① `set -u` 下 `HOME` 为空时脚本第一行就炸，改成先 `dscl` 反查再赋值；② `$LABEL（` 这类「变量紧跟全角字符」被 bash 当成变量名一部分（`LABEL…: unbound variable`），统一改成 `${LABEL}`；③ 验收脚本里的 `set -e`/`set +e` 让一次预期失败的构建直接终止脚本，改为全程不使用 errexit，失败靠 `MANUAL/FAIL` 检查项表达。

## 参考文档

- [[project-memory/任务计划/生物识别解锁与授权策略|任务计划书 · 生物识别解锁与授权策略]]（本次追加的续签步骤表与未决项）。
- [[docs/验收/验收总览|验收总览]]（验收惯例、artifacts 布局与复测清单）。
- `packaging/macos/build-biometric-app.sh` 的 `--status-file` / `--no-probe` / `failure_class` 契约（续签脚本据此判定失败类别并转发人工步骤）。

## 文档产物

- 新建 `packaging/macos/install-biometric-app.sh`（部署 + 到期判断 + 重建）。
- 新建 `packaging/macos/install-biometric-renew.sh`（LaunchAgent 每周续签，含 `--install/--status/--run-now/--uninstall/--plist-dir`）。
- 更新 `packaging/macos/install.sh`（默认 `--deploy-only` 部署 `.app`、`KEYKOI_BIOMETRIC_APP=0` 关闭、plist 写 `KEYKOI_BIOMETRIC_HELPER`、失败不中断）。
- 新建 `tests/acceptance/biometric-renewal.sh`，产出 `docs/验收/artifacts/biometric-renewal/result.json`。
- 新建 [[docs/指南/生物识别助手续签与部署|生物识别助手部署与续签]]（部署路径、7 天到期原因、自动续签机制、付费账号 / `-allowProvisioningUpdates` / `LAContext` 三方案与安全代价、排障表）。
- 更新 [[docs/索引/使用指南|使用指南索引]]：新增上述指南一行。
- 更新 [[docs/验收/验收总览|验收总览]]：结果总表新增一行、复测清单新增一条命令。
- 更新 [[project-memory/任务计划/生物识别解锁与授权策略|任务计划书]]：追加「部署与描述文件续签」步骤表，刷新当前进度与未决项。
- 更新 [[project-memory/工作流/生物识别解锁与授权策略|生物识别解锁与授权策略]]：当前状态、阻塞与下一步、相关文档、近期记录。

## 剩余工作与下一步

1. 需要重启服务才生效的一步：重跑 `bash packaging/macos/install.sh`，让运行中的 `com.keykoi.keykoid` 从新 plist 拿到 `KEYKOI_BIOMETRIC_HELPER`（本次没有重启用户已加载的服务，只改了脚本）。
2. 真实指纹手势仍未自动验证：在会弹指纹框的机器上人工跑一次 `keykoi vault enroll-biometric` → `keykoi unlock --biometric`。
3. 风险与边界：免费 Personal Team 的描述文件上限就是 7 天，续签是「重新签发」；描述文件仍有效时 Xcode 复用旧文件、不推进 `ExpirationDate`，只有过期/缺失才拿到新窗口，所以每周检查是必须的（`next fire` 只会在 Mac 唤醒且用户已登录时触发，长期关机需人工补跑 `--build-if-needed`）。离线会落到 `failure_class=network`，日志里有四步人工指引。要真正降频只有付费开发者账号（1 年）方案，见指南「可选方案 A」。
