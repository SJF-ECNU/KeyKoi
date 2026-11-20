package vault

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// BiometricHelperEnv 是助手路径的环境变量名。keykoi / keykoid 通过它指向
// 打包好的 `KeyKoi Biometric.app` 或其中的可执行文件，默认仍是原路径约定。
const BiometricHelperEnv = "KEYKOI_BIOMETRIC_HELPER"

// BiometricHelperName 是助手可执行文件名（裸二进制与 .app 内一致）。
const BiometricHelperName = "keykoi-biometric"

// BiometricAppBundleName 是打包后的 .app 目录名。
const BiometricAppBundleName = "KeyKoi Biometric.app"

// ResolveHelperPath 依次尝试显式参数、KEYKOI_BIOMETRIC_HELPER、keykoi/keykoid
// 同目录的裸二进制或 .app 包，最后 PATH。全部失败返回空字符串，表示当前环境
// 不支持生物识别（上层据此回退主密码并报告 AUTH_UNAVAILABLE）。
//
// 环境变量可以写成三种形态，都会被归一化成最终要执行的路径：
//   - 裸可执行文件：.../bin/keykoi-biometric
//   - .app 包：.../KeyKoi Biometric.app → .../Contents/MacOS/keykoi-biometric
//   - 包内目录：.../KeyKoi Biometric.app/Contents/MacOS → 同目录可执行文件
func ResolveHelperPath(explicit string) string {
	if explicit != "" {
		return NormalizeHelperPath(explicit)
	}
	if env := os.Getenv(BiometricHelperEnv); env != "" {
		return NormalizeHelperPath(env)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, candidate := range []string{
			filepath.Join(dir, BiometricHelperName),
			filepath.Join(dir, BiometricAppBundleName, "Contents", "MacOS", BiometricHelperName),
		} {
			if st, statErr := os.Stat(candidate); statErr == nil && !st.IsDir() {
				return candidate
			}
		}
	}
	if path, err := exec.LookPath(BiometricHelperName); err == nil {
		return path
	}
	return ""
}

// NormalizeHelperPath 把 .app 包或包内目录换算成包内的可执行文件路径；
// 其他输入（裸二进制、不存在的路径）原样返回，让调用方在启动时拿到真实错误。
func NormalizeHelperPath(path string) string {
	if path == "" {
		return ""
	}
	cleaned := filepath.Clean(path)
	if strings.HasSuffix(cleaned, ".app") {
		return filepath.Join(cleaned, "Contents", "MacOS", BiometricHelperName)
	}
	if st, err := os.Stat(cleaned); err == nil && st.IsDir() {
		bundleExe := filepath.Join(cleaned, "Contents", "MacOS", BiometricHelperName)
		if st, err := os.Stat(bundleExe); err == nil && !st.IsDir() {
			return bundleExe
		}
		inner := filepath.Join(cleaned, BiometricHelperName)
		if st, err := os.Stat(inner); err == nil && !st.IsDir() {
			return inner
		}
	}
	return cleaned
}
