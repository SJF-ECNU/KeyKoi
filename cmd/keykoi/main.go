// Command keykoi 是 KeyKoi 管理 CLI 与原生凭证助手入口。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"keykoi/internal/ipcclient"
	"keykoi/internal/osruntime"
	"keykoi/internal/shim"
)

type globalOptions struct {
	socket  string
	dataDir string
	json    bool
}

var g globalOptions

func main() {
	// 无感入口：当本进程以已安装 shim 的名字被调用时，直接按原命令执行。
	if handled, code := shim.MaybeRun(); handled {
		os.Exit(code)
	}
	args := os.Args[1:]
	// 与 shim 共用同一套数据目录解析：安装目录下的 data/ 优先于默认目录。
	g.dataDir = osruntime.ResolveDataDir()
	g.socket = os.Getenv("KEYKOI_SOCKET")
	// 显式 socket 优先于数据目录，和参数出现次序无关。
	var rest []string
	for i := 0; i < len(args); i++ {
		// `--` 之后全部属于被包装命令：不再扫描全局参数，否则工具自身的
		// --socket / --json 之类参数会被 KeyKoi 吃掉。
		if args[i] == "--" {
			rest = append(rest, args[i])
			rest = append(rest, args[i+1:]...)
			break
		}
		switch args[i] {
		case "--socket", "--data-dir":
			if i+1 == len(args) {
				fmt.Fprintf(os.Stderr, "%s requires a value\n", args[i])
				os.Exit(2)
			}
			if args[i] == "--socket" {
				g.socket = args[i+1]
			} else {
				g.dataDir = args[i+1]
			}
			i++
		case "--json":
			g.json = true
		default:
			// ssh-agent 自身声明了 --socket（agent 监听路径）；对这一入口不再
			// 继续剥离全局参数，否则 `ssh-agent --socket X` 会把监听路径当成后台
			// IPC socket。其它子命令仍允许把全局参数写在后面。
			if args[i] == "ssh-agent" {
				rest = append(rest, args[i:]...)
				i = len(args)
				continue
			}
			rest = append(rest, args[i])
		}
	}
	if g.socket == "" {
		g.socket = osruntime.SocketPath(g.dataDir)
	}
	if len(rest) == 0 {
		usage()
		os.Exit(2)
	}
	cmd := rest[0]
	// 带子命令的入口把第二个参数当子命令，其余入口把后续参数整体交给标志解析。
	subCommands := map[string]bool{
		"credential": true, "credentials": true, "binding": true, "bindings": true,
		"grant": true, "grants": true, "helper": true, "lease": true,
		"integration": true, "oauth": true, "shim": true, "git": true,
		"auth": true, "vault": true,
	}
	sub := ""
	var tail []string
	if subCommands[cmd] && len(rest) > 1 {
		sub = rest[1]
		tail = rest[2:]
	} else if len(rest) > 1 {
		tail = rest[1:]
	}
	var err error
	switch cmd {
	case "status":
		err = cmdStatus()
	case "support":
		err = cmdSupport()
	case "init":
		err = cmdInit(tail)
	case "unlock":
		err = cmdUnlock(tail)
	case "auth":
		err = cmdAuth(sub, tail)
	case "vault":
		err = cmdVault(sub, tail)
	case "lock":
		err = cmdLock()
	case "credential", "credentials":
		err = cmdCredential(sub, tail)
	case "binding", "bindings":
		err = cmdBinding(sub, tail)
	case "grant", "grants":
		err = cmdGrant(sub, tail)
	case "whoami":
		var subject map[string]any
		if err = ipcclient.New(g.socket, "").Get("/v1/subjects/current", &subject); err == nil {
			if g.json {
				err = printJSON(subject)
			} else {
				fmt.Printf("%s (%s)\n", subject["label"], subject["key"])
			}
		}
	case "audit":
		err = cmdAudit(tail)
	case "lease":
		err = cmdLease(sub, tail)
	case "helper":
		err = cmdHelper(sub, tail)
	case "measure":
		err = cmdMeasure(tail)
	case "backup":
		err = cmdBackup(tail)
	case "restore":
		err = cmdRestore(tail)
	case "ui":
		err = cmdUI(tail)
	case "doctor":
		err = cmdDoctor()
	case "run":
		err = cmdRun(tail)
	case "integration":
		err = cmdIntegration(sub, tail)
	case "ssh-agent":
		err = cmdSSHAgent(tail)
	case "db-proxy":
		err = cmdDBProxy(tail)
	case "tls-proxy":
		err = cmdTLSProxy(tail)
	case "sign":
		err = cmdSign(tail)
	case "oauth":
		err = cmdOAuth(sub, tail)
	case "shim":
		err = cmdShim(sub, tail)
	case "git":
		err = cmdGit(sub, tail)
	case "help", "--help", "-h":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`KeyKoi 本机凭证中介

用法: keykoi [--socket PATH] [--data-dir DIR] [--json] <命令>

命令:
  status                         后台、锁定与交付状态
  support                        交付模式与验证状态展示文案
  init [--password-stdin]        初始化加密密钥库
  unlock [--biometric] [--password-stdin]
                                 解锁密钥库；--biometric 用 Touch ID，不可用时回退主密码
  lock                           锁定并停止新的用钥
  credential list|add|rotate|disable
  binding list|add
  grant list|add|revoke|approve|subjects|register-agent
                                 add --auth once|window:300|per-use|permanent
  lease revoke <lease-id>
  audit [--limit N]
  backup <path>                  密文备份
  restore <path>                 恢复密文备份（默认锁定，授权待复核）
  whoami                         查看当前用钥主体
  auth status                    生物识别可用性、登记状态与授权策略
  auth verify [--method biometric|password] [--grant ID --mode M]
                                 显式验证（CLI 侧证明身份或为一次用钥预验证）
  vault enroll-biometric         把根密钥登记到 macOS Keychain（biometryCurrentSet）
  ui [--admin ADDR] [--no-open]  一键登录看板（令牌经 URL fragment 传递，页面读完即清除）
  doctor                         本机诊断
  helper aws --binding ID         AWS CLI credential_process 助手
  helper git --binding ID --action get|store|erase
  measure ...                    直连与代理测量
  integration detect|plan|attach|verify|detach
  shim install|list|remove        无感入口（把原命令指向 keykoi）
  git setup|teardown              git 走网关：仓库只拿中介令牌
  run [--mode runtime|proxy] --exe CMD [--binding B | --route R] -- CMD...
                                 受管理运行（runtime 注入真实值，proxy 只注入会话令牌/网关地址）
  ssh-agent / db-proxy / tls-proxy / sign / oauth ...
`)
}

func client() *ipcclient.Client {
	token := ""
	if b, err := os.ReadFile(filepath.Join(g.dataDir, "admin.token")); err == nil {
		token = strings.TrimSpace(string(b))
	}
	return ipcclient.New(g.socket, token)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func readPassword(fromStdin bool) ([]byte, error) {
	if fromStdin {
		var pw string
		if _, err := fmt.Fscanln(os.Stdin, &pw); err == nil && pw != "" {
			return []byte(pw), nil
		}
	}
	fmt.Fprint(os.Stderr, "master password: ")
	pw, err := readPasswordNoEcho()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, fmt.Errorf("empty password")
	}
	return pw, nil
}

func cmdStatus() error {
	st, err := client().Status()
	if err != nil {
		return err
	}
	if g.json {
		return printJSON(st)
	}
	fmt.Printf("state:      %v\n", st["state"])
	fmt.Printf("locked:     %v\n", st["locked"])
	fmt.Printf("gateway:    %v\n", st["gateway"])
	fmt.Printf("admin:      %v\n", st["admin"])
	fmt.Printf("credentials:%v\n", st["credentials"])
	fmt.Printf("epoch:      %v\n", st["epoch"])
	fmt.Printf("backend:    %v\n", st["backend"])
	return nil
}

func cmdSupport() error {
	var out struct {
		Support []map[string]any `json:"support"`
	}
	if err := client().Get("/v1/support", &out); err != nil {
		return err
	}
	if g.json {
		return printJSON(out.Support)
	}
	for _, s := range out.Support {
		sees := "否"
		if v, ok := s["tool_sees_real_value"].(bool); ok && v {
			sees = "是"
		}
		fmt.Printf("%-16s %-12s 工具看到真实值: %s\n  %s\n", s["label"], s["status"], sees, s["summary"])
	}
	return nil
}
