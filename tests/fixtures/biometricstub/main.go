// Command biometricstub 是 macOS 生物识别助手的测试替身。
//
// 它实现与 packaging/macos/keykoi-biometric.swift 相同的子命令与退出码，
// 把「根密钥」写进一个临时目录，并按 $KEYKOI_BIOMETRIC_STUB_DIR/mode 的内容
// 模拟各种环境（ok / unavailable / no_biometry / cancel / missing），
// 让生物识别授权策略可以在无人值守的验收里被完整覆盖。
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	exitOK          = 0
	exitNoBiometry  = 2
	exitCancelled   = 3
	exitUnavailable = 4
)

func main() {
	dir := os.Getenv("KEYKOI_BIOMETRIC_STUB_DIR")
	if dir == "" {
		fmt.Fprintln(os.Stderr, "KEYKOI_BIOMETRIC_STUB_DIR is required")
		os.Exit(exitUnavailable)
	}
	args := os.Args[1:]
	command := "available"
	account := "keykoi-root"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--account":
			if i+1 < len(args) {
				account = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "--") {
				command = args[i]
			}
		}
	}
	logCall(dir, command, account)
	mode := readMode(dir)

	switch command {
	case "available":
		switch mode {
		case "no_biometry":
			fmt.Fprintln(os.Stderr, "Touch ID is not enrolled on this Mac")
			os.Exit(exitNoBiometry)
		case "unavailable":
			fmt.Fprintln(os.Stderr, "no GUI session; biometric verification is unavailable")
			os.Exit(exitUnavailable)
		}
		fmt.Println("available")
		os.Exit(exitOK)
	case "store":
		if exit := modeExit(mode); exit != exitOK {
			os.Exit(exit)
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read stdin:", err)
			os.Exit(exitUnavailable)
		}
		payload := strings.TrimSpace(string(data))
		if payload == "" {
			fmt.Fprintln(os.Stderr, "empty root key on stdin")
			os.Exit(exitUnavailable)
		}
		if err := os.WriteFile(itemPath(dir, account), []byte(payload), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write item:", err)
			os.Exit(exitUnavailable)
		}
		fmt.Println("stored", account)
		os.Exit(exitOK)
	case "load":
		if exit := modeExit(mode); exit != exitOK {
			os.Exit(exit)
		}
		data, err := os.ReadFile(itemPath(dir, account))
		if err != nil {
			fmt.Fprintf(os.Stderr, "no enrolled root key for account %s\n", account)
			os.Exit(exitUnavailable)
		}
		fmt.Println(strings.TrimSpace(string(data)))
		os.Exit(exitOK)
	case "delete":
		_ = os.Remove(itemPath(dir, account))
		fmt.Println("deleted", account)
		os.Exit(exitOK)
	}
	fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", command)
	os.Exit(exitUnavailable)
}

func modeExit(mode string) int {
	switch mode {
	case "no_biometry":
		return exitNoBiometry
	case "cancel":
		return exitCancelled
	case "unavailable":
		return exitUnavailable
	}
	return exitOK
}

func readMode(dir string) string {
	if data, err := os.ReadFile(filepath.Join(dir, "mode")); err == nil {
		if mode := strings.TrimSpace(string(data)); mode != "" {
			return mode
		}
	}
	if mode := strings.TrimSpace(os.Getenv("KEYKOI_BIOMETRIC_STUB_MODE")); mode != "" {
		return mode
	}
	return "ok"
}

func itemPath(dir, account string) string {
	return filepath.Join(dir, account+".key")
}

func logCall(dir, command, account string) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "calls.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s %s\n", command, account)
}
