package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"keykoi/internal/ipcclient"
	"keykoi/internal/osruntime"
	"keykoi/internal/ssha"
)

// cmdSSHAgent 运行受保护的本地 SSH agent。
//
// 私钥只在中介内存在，agent 每次签名都重新申请；撤销 sign 许可后立即失效。
func cmdSSHAgent(args []string) error {
	fs := flag.NewFlagSet("ssh-agent", flag.ContinueOnError)
	binding := fs.String("binding", "", "binding id whose sign grant backs this agent")
	sessionToken := fs.String("session-token", "", "existing session token (default: create a non-admin session)")
	agentSocket := fs.String("agent-socket", "", "agent unix socket path")
	// 本子命令的 --socket 是 agent 监听路径（全局 --socket 只出现在子命令之前）。
	socketAlias := fs.String("socket", "", "agent unix socket path (this subcommand only)")
	writeShell := fs.Bool("write-shell-env", false, "export SSH_AUTH_SOCK in the shell startup file")
	shellRC := fs.String("shell-rc", "", "shell startup file (default: ~/.zshrc)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *binding == "" {
		return fmt.Errorf("--binding is required: the agent only serves keys reachable through one sign grant")
	}

	sockPath := *agentSocket
	if sockPath == "" {
		sockPath = *socketAlias
	}
	if sockPath == "" {
		// main() 会把全局 --socket 从子命令参数中剥离，因此这里再看一次原始命令行。
		sockPath = sshAgentSocketFromArgv(os.Args[1:])
	}
	if sockPath == "" {
		sockPath = filepath.Join(g.dataDir, "ssh-agent.sock")
	}

	if *writeShell {
		rc := *shellRC
		if rc == "" {
			home, _ := os.UserHomeDir()
			rc = filepath.Join(home, ".zshrc")
		}
		line := `export SSH_AUTH_SOCK="` + sockPath + `"`
		if err := updateManagedBlock(rc, "ssh-agent", line); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote SSH_AUTH_SOCK to %s; open a new shell or run: source %s\n", rc, rc)
	}

	// agent 只使用非管理员会话：不读取本机管理令牌。
	daemonSocket := sshAgentDaemonSocket(sockPath)
	client := ipcclient.New(daemonSocket, "")
	token := *sessionToken
	if token == "" {
		sess, err := client.CreateSession("ssh-agent", false)
		if err != nil {
			return err
		}
		token = sess.Token
	}

	provider := ssha.NewIPCProvider(client, token)
	// 会话续期：Agent 会长时间驻留，后台重启或会话到期后必须能重建会话，
	// 否则监听还在但每次签名都失败。续期只重建普通会话，不改变任何授权。
	provider.Renew = func(ctx context.Context) (string, error) {
		sess, err := client.CreateSession("ssh-agent", false)
		if err != nil {
			return "", err
		}
		return sess.Token, nil
	}
	ag := ssha.NewAgent(provider, *binding)

	// 启动前枚举一次：会话无效或没有 sign 许可时立刻报错，而不是静默空转。
	infos, err := provider.ListKeys(context.Background())
	if err != nil {
		return err
	}
	served := 0
	for _, info := range infos {
		if info.BindingID != *binding || info.PublicKey == "" {
			continue
		}
		served++
		// 只输出非秘密元数据：指纹与标签。
		fmt.Fprintf(os.Stderr, "key: %s %s\n", info.Fingerprint, info.Label)
	}
	if served == 0 {
		fmt.Fprintf(os.Stderr, "warning: no ssh_key credential is reachable through binding %s yet\n", *binding)
	}

	srv := ssha.NewServer(sockPath, ag)
	if err := srv.Listen(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	// 与 ssh-agent -s 的输出形状一致，便于 eval 与脚本读取。
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", sockPath)
	fmt.Fprintf(os.Stderr, "SSH_AGENT_PID=%d; export SSH_AGENT_PID;\n", os.Getpid())
	fmt.Fprintf(os.Stderr, "ssh-agent listening: binding=%s daemon=%s keys=%d\n", *binding, daemonSocket, served)
	return srv.Serve()
}

// sshAgentSocketFromArgv 从原始命令行读取 agent socket 参数。
//
// 只认 --agent-socket：--socket 是后台 IPC 的全局参数，main() 会把它剥离并用于
// 连接 keykoid。若在这里也把它当 agent 监听路径，`keykoi --socket X ssh-agent`
// 就会去覆盖后台正在使用的 socket。
func sshAgentSocketFromArgv(argv []string) string {
	names := []string{"--agent-socket", "-agent-socket"}
	for _, name := range names {
		for i, arg := range argv {
			if arg == name && i+1 < len(argv) {
				return argv[i+1]
			}
			if strings.HasPrefix(arg, name+"=") {
				return strings.TrimPrefix(arg, name+"=")
			}
		}
	}
	return ""
}

// sshAgentDaemonSocket 计算后台 IPC socket。
// KEYKOI_SOCKET 与 KEYKOI_DATA_DIR 优先；否则用当前数据目录，
// 并在全局 socket 明确存在且不是 agent 自身时沿用全局值。
func sshAgentDaemonSocket(agentSocket string) string {
	if v := os.Getenv("KEYKOI_SOCKET"); v != "" {
		return v
	}
	dir := g.dataDir
	if v := os.Getenv("KEYKOI_DATA_DIR"); v != "" {
		dir = v
	}
	def := osruntime.SocketPath(dir)
	if g.socket != "" && g.socket != agentSocket {
		if _, err := os.Stat(g.socket); err == nil {
			return g.socket
		}
	}
	return def
}
