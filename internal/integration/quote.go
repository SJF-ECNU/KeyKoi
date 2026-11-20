package integration

import "strings"

// shellSpecial 是需要在命令行中引用的字符集合。
const shellSpecial = " \t\n\r\"'\\$`&|;<>(){}[]*?!#~"

// ShellQuoteCommand 按 POSIX shell 引用规则拼接一条命令。
//
// git 的 credential.helper 值由 sh 执行，AWS 的 credential_process 由 shlex
// 拆分，两者都接受单引号引用，因此含空格或特殊字符的参数一律加单引号，
// 不再直接拼接未转义的字符串。不需要引用的参数保持原样，便于阅读。
func ShellQuoteCommand(parts ...string) string {
	quoted := make([]string, 0, len(parts))
	for _, p := range parts {
		quoted = append(quoted, ShellQuotePart(p))
	}
	return strings.Join(quoted, " ")
}

// ShellQuotePart 引用单个命令行参数。
func ShellQuotePart(s string) string {
	if s != "" && !strings.ContainsAny(s, shellSpecial) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// GitCredentialHelper 构造 git credential.helper 的取值：git 会以 sh 执行
// 去掉前导 "!" 后的整行，因此这里按 sh 语法引用，路径含空格也能启动。
func GitCredentialHelper(bin, bindingID string) string {
	return "!" + ShellQuoteCommand(bin, "helper", "git-token", "--binding", bindingID)
}
