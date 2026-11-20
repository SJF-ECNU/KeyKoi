// keykoi-biometric: macOS 生物识别（Touch ID / Optic ID）助手。
//
// 设计约束：根密钥是 32 字节随机值，由 keykoid 通过 stdin 以 base64 交给本助手，
// 再由 Security 框架写入 Keychain 的 generic password 条目，ACL 使用
// kSecAccessControlBiometryCurrentSet。指纹本身不参与密钥派生：
//   - 只有当前登记的指纹集合可以通过 ACL 取出条目；
//   - 新增或删除指纹会使条目失效（biometryCurrentSet 语义）；
//   - 主密码始终是唯一可恢复的入口。
//
// 子命令：
//   store   --account keykoi-root     stdin 读 base64 根密钥并写入 Keychain
//   load    --account keykoi-root     触发系统验证，stdout 输出 base64 根密钥
//   available                         报告当前会话能否使用生物识别
//   delete  --account keykoi-root     删除条目
//
// 退出码（与 internal/vault/biometric.go 对齐）：
//   0 成功 · 2 无生物识别硬件或未登记 · 3 用户取消/验证失败 · 4 不可用/非 GUI 会话

import Foundation
import LocalAuthentication
import Security

let keychainService = "com.keykoi.biometric"
let defaultAccount = "keykoi-root"
let rootKeyLength = 32
/// 重新登记用的暂存槽：正式账号是 `<account>`，暂存账号是 `<account>.pending`。
/// 新值先带同一套生物识别 ACL 落在这里并实际读回校验；只有校验成功后才用
/// SecItemUpdate 原子替换正式项，避免撤旧后写新失败而丢失已登记的根密钥。
let pendingSuffix = ".pending"

enum HelperExit: Int32 {
    case ok = 0
    case noBiometry = 2
    case cancelled = 3
    case unavailable = 4
}

struct HelperFailure: Error {
    let exit: HelperExit
    let message: String
}

func fail(_ exit: HelperExit, _ message: String) -> HelperFailure {
    HelperFailure(exit: exit, message: message)
}

func writeStderr(_ text: String) {
    FileHandle.standardError.write(Data((text + "\n").utf8))
}

func laContextHint(_ error: Error?) -> HelperExit {
    guard let laError = error as? LAError else { return .unavailable }
    switch laError.code {
    case .biometryNotEnrolled, .biometryNotAvailable, .biometryLockout:
        return .noBiometry
    case .userCancel, .userFallback, .authenticationFailed, .appCancel, .systemCancel:
        return .cancelled
    case .notInteractive, .invalidContext, .passcodeNotSet:
        return .unavailable
    default:
        return .unavailable
    }
}

/// available 检查：不弹窗，只问系统当前会话能否做生物识别。
func ensureAvailable(_ context: LAContext) throws {
    var authError: NSError?
    let ok = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError)
    if !ok {
        let message = authError?.localizedDescription ?? "biometrics cannot be evaluated in this session"
        let exit = laContextHint(authError)
        throw fail(exit, message)
    }
    if context.biometryType == .none {
        throw fail(.noBiometry, "this Mac has no enrolled biometric hardware")
    }
}

/// 生物识别 ACL 只对具备钥匙串访问组权限的签名二进制开放。裸编译产物或
/// 只做 ad-hoc 签名的产物会被系统以 errSecMissingEntitlement 拒绝，这里给出
/// 可操作的提示而不是一个裸状态码。
let enrollmentEntitlementHint = """
keychain rejected the biometric access control (errSecMissingEntitlement, -34018).
Sign this helper with a code-signing identity and the keychain-access-groups entitlement
(for example: codesign --force --sign "Apple Development: ..." --entitlements keykoi-biometric.entitlements keykoi-biometric),
or ship it inside a signed .app bundle, then run 'keykoi vault enroll-biometric' again.
The master password remains the fallback until then.
"""

func baseQuery(account: String) -> [String: Any] {
    // 生物识别 ACL 只在数据保护钥匙串（iOS 风格）中受支持，必须显式选择它；
    // 传统文件钥匙串会以 errSecMissingEntitlement (-34018) 拒绝。
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainService,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
    ]
}

func pendingAccount(_ account: String) -> String {
    account + pendingSuffix
}

/// 把账号与条目属性合成一条完整条目（写入用）。
func itemQuery(account: String, attributes: [String: Any]) -> [String: Any] {
    var item = baseQuery(account: account)
    for (key, value) in attributes {
        item[key] = value
    }
    return item
}

/// 清掉暂存槽（幂等；不关心是否原本存在）。
func clearPendingSlot(_ account: String) {
    SecItemDelete(baseQuery(account: pendingAccount(account)) as CFDictionary)
}

/// 写入失败的统一错误：明确说明旧条目没有被改动，避免用户以为根密钥丢了。
func addFailure(_ status: OSStatus) -> HelperFailure {
    if status == errSecMissingEntitlement {
        return fail(.unavailable, enrollmentEntitlementHint)
    }
    return fail(.unavailable, "keychain add failed with status \(status); the previously enrolled root key was left untouched")
}

func storeRootKey(account: String, root: Data) throws {
    guard root.count == rootKeyLength else {
        throw fail(.unavailable, "root key must be \(rootKeyLength) bytes, got \(root.count)")
    }
    let context = LAContext()
    context.localizedReason = "用 Touch ID 重新登记钥鲤 KeyKoi 密钥库"
    try ensureAvailable(context)

    var aclError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .biometryCurrentSet,
        &aclError
    ) else {
        let message = aclError?.takeRetainedValue().localizedDescription ?? "cannot build a biometric access control"
        throw fail(.unavailable, message)
    }

    let attributes: [String: Any] = [
        kSecValueData as String: root,
        kSecAttrAccessControl as String: access,
        kSecAttrLabel as String: "KeyKoi vault root key (Touch ID)",
        kSecAttrDescription as String: "root key for the KeyKoi vault; protected by the current biometric set",
    ]

    // 首次登记：直接写正式账号，本来就没有旧条目要保。
    let addStatus = SecItemAdd(itemQuery(account: account, attributes: attributes) as CFDictionary, nil)
    if addStatus == errSecSuccess {
        clearPendingSlot(account)
        return
    }
    guard addStatus == errSecDuplicateItem else {
        throw addFailure(addStatus)
    }

    // 重新登记（缺陷 32）：任何时刻都不能先撤掉正式旧项再赌一次写入。
    //   1) 把带同一套生物识别 ACL 的完整新条目写进暂存槽；失败时正式旧项未动；
    //   2) 实际读回暂存项并逐字节比对。只有新根密钥确实可读取，才允许替换正式项；
    //   3) 用 SecItemUpdate 原子替换正式项；系统不支持更新 ACL 时宁可登记失败，
    //      也绝不退到「删除正式旧项 + SecItemAdd」。
    clearPendingSlot(account)
    let stagingStatus = SecItemAdd(itemQuery(account: pendingAccount(account), attributes: attributes) as CFDictionary, nil)
    guard stagingStatus == errSecSuccess else {
        throw addFailure(stagingStatus)
    }

    do {
        guard let stagedRoot = try copyRootKey(account: pendingAccount(account), context: context),
              stagedRoot == root else {
            throw fail(.unavailable, "keychain staging verification failed; the previously enrolled root key is unchanged")
        }
    } catch {
        clearPendingSlot(account)
        throw error
    }

    var updateQuery = baseQuery(account: account)
    updateQuery[kSecUseAuthenticationContext as String] = context
    let updateStatus = SecItemUpdate(updateQuery as CFDictionary, attributes as CFDictionary)
    switch updateStatus {
    case errSecSuccess:
        // 正式条目已经是刚才读回验证过的新值，旧值被原子替换，没有空档。
        clearPendingSlot(account)
        return
    case errSecMissingEntitlement:
        clearPendingSlot(account)
        throw fail(.unavailable, enrollmentEntitlementHint)
    case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
        // 用户在替换时取消了生物识别：按「新值没有生效」处理，旧条目原样保留。
        clearPendingSlot(account)
        throw fail(.cancelled, "biometric confirmation for replacing the keychain item was cancelled; the previously enrolled root key is unchanged")
    case errSecParam, errSecUnimplemented:
        // 不能原子更新 ACL 时安全失败。暂存项已验证可读，但它不能替代正式项的
        // 安全语义；清掉暂存项并保留正式旧项，调用方可修复环境后重试。
        clearPendingSlot(account)
        throw fail(.unavailable, "keychain cannot atomically replace the biometric access control (status \(updateStatus)); the previously enrolled root key is unchanged")
    default:
        // 其它错误一律不动旧条目：宁可这次登记失败，也不留下没有根密钥的状态。
        clearPendingSlot(account)
        throw fail(.unavailable, "keychain update failed with status \(updateStatus); the previously enrolled root key is unchanged")
    }
}

/// 读取一个账号下的根密钥：条目不存在返回 nil，其它错误抛出。
func copyRootKey(account: String, context: LAContext) throws -> Data? {
    var query = baseQuery(account: account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    switch status {
    case errSecSuccess:
        guard let data = result as? Data else {
            throw fail(.unavailable, "keychain returned an unexpected item")
        }
        guard data.count == rootKeyLength else {
            throw fail(.unavailable, "stored root key has \(data.count) bytes")
        }
        return data
    case errSecItemNotFound:
        return nil
    case errSecUserCanceled, errSecAuthFailed, errSecInteractionNotAllowed:
        throw fail(.cancelled, "biometric verification for the keychain item was cancelled")
    case errSecMissingEntitlement:
        throw fail(.unavailable, enrollmentEntitlementHint)
    default:
        throw fail(.unavailable, "keychain read failed with status \(status)")
    }
}

func loadRootKey(account: String) throws -> Data {
    let context = LAContext()
    context.localizedReason = "用 Touch ID 解锁钥鲤 KeyKoi 密钥库"
    try ensureAvailable(context)

    // 把 LAContext 交给 SecItemCopyMatching，由 Security 在需要时弹一次系统验证；
    // 条目不存在时不会打扰用户，也不会出现「验证两次」。
    if let root = try copyRootKey(account: account, context: context) {
        return root
    }
    // 兼容旧版重新登记被打断后留下的暂存项；当前实现不会再删除正式旧项，
    // 所以正常中断时上面的正式项优先，暂存项只作为旧状态的恢复入口。
    if let root = try copyRootKey(account: pendingAccount(account), context: context) {
        writeStderr("note: root key came from the staging slot (\(pendingAccount(account))); re-run 'store' to finish the replacement")
        return root
    }
    throw fail(.unavailable, "no enrolled root key for account \(account)")
}

func deleteRootKey(account: String) throws {
    let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
    // 暂存槽属于同一次登记的一部分，跟着一起删，避免留下旧状态。
    let pendingStatus = SecItemDelete(baseQuery(account: pendingAccount(account)) as CFDictionary)
    // 条目原本不存在也算成功：删除是幂等操作。
    let statuses = [status, pendingStatus]
    for value in statuses where value != errSecSuccess && value != errSecItemNotFound {
        throw fail(.unavailable, "keychain delete failed with status \(value)")
    }
}

func readStdin() -> Data {
    var data = Data()
    let handle = FileHandle.standardInput
    while true {
        let chunk = handle.availableData
        if chunk.isEmpty { break }
        data.append(chunk)
    }
    return data
}

func parseArguments() -> (command: String, account: String) {
    let args = Array(CommandLine.arguments.dropFirst())
    var command = "available"
    var account = defaultAccount
    var index = 0
    while index < args.count {
        let arg = args[index]
        switch arg {
        case "--account":
            if index + 1 < args.count {
                account = args[index + 1]
                index += 2
                continue
            }
        case "--help", "-h":
            command = "help"
        default:
            if !arg.hasPrefix("--") && command == "available" && index == 0 {
                command = arg
            }
        }
        index += 1
    }
    return (command, account)
}

func run() -> Int32 {
    let (command, account) = parseArguments()
    do {
        switch command {
        case "available":
            let context = LAContext()
            try ensureAvailable(context)
            print("available")
            return HelperExit.ok.rawValue
        case "store":
            let raw = String(data: readStdin(), encoding: .utf8) ?? ""
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard let root = Data(base64Encoded: trimmed), root.count == rootKeyLength else {
                throw fail(.unavailable, "stdin must contain a base64 encoded \(rootKeyLength)-byte root key")
            }
            try storeRootKey(account: account, root: root)
            print("stored \(account)")
            return HelperExit.ok.rawValue
        case "load":
            let root = try loadRootKey(account: account)
            print(root.base64EncodedString())
            return HelperExit.ok.rawValue
        case "delete":
            try deleteRootKey(account: account)
            print("deleted \(account)")
            return HelperExit.ok.rawValue
        case "help":
            print("usage: keykoi-biometric store|load|available|delete [--account name]")
            return HelperExit.ok.rawValue
        default:
            throw fail(.unavailable, "unknown subcommand \(command)")
        }
    } catch let failure as HelperFailure {
        writeStderr(failure.message)
        return failure.exit.rawValue
    } catch {
        writeStderr("unexpected failure: \(error.localizedDescription)")
        return HelperExit.unavailable.rawValue
    }
}

// 入口用 @main 而不是顶层语句：裸二进制（build-biometric.sh 的 swiftc）和
// .app 包（Xcode 应用的 -parse-as-library 编译）都必须接受同一份源码。
@main
enum KeyKoiBiometricMain {
    static func main() {
        exit(run())
    }
}
