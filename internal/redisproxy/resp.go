package redisproxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// readLimits 限制一条 RESP 值能占用的字节、元素与嵌套深度。
//
// 认证前客户端还没被授权，解析器必须自己兜底：长度前缀与嵌套深度都不能无界，
// 否则一个未认证连接就能让代理按对方声明的体积分配内存。
type readLimits struct {
	// maxLine 是单行（类型字节 + 长度/内容所在行）的字节上限。
	maxLine int
	// maxBulk 是单个 bulk/blob 声明的长度上限。
	maxBulk int
	// maxArray 是数组、集合、map、push 的元素个数上限（map 按 2 倍计）。
	maxArray int
	// maxDepth 是容器嵌套深度上限。
	maxDepth int
	// maxTotal 是单条消息累计字节上限；0 表示不累计。
	maxTotal int
}

var (
	// authLimits 用于认证前的握手：只放行 AUTH/HELLO 这类小命令，
	// 仍然比正常握手（AUTH 令牌 + HELLO 选项）宽松得多。
	authLimits = readLimits{
		maxLine:  4 << 10,
		maxBulk:  64 << 10,
		maxArray: 64,
		maxDepth: 4,
		maxTotal: 512 << 10,
	}
	// relayLimits 用于认证后的透明转发：与 Redis 默认 proto-max-bulk-len 对齐，
	// 不像认证前那样收紧，避免改变正常客户端的可用命令范围。
	relayLimits = readLimits{
		maxLine:  64 << 10,
		maxBulk:  512 << 20,
		maxArray: 1 << 20,
		maxDepth: 32,
	}
)

// readBudget 累计一条消息已解析的字节数，用于 maxTotal。
type readBudget struct {
	lim  readLimits
	used int
}

func (b *readBudget) add(n int) error {
	b.used += n
	if b.lim.maxTotal > 0 && b.used > b.lim.maxTotal {
		return fmt.Errorf("redisproxy: message exceeds %d bytes", b.lim.maxTotal)
	}
	return nil
}

// readCommand 读取一条完整的 RESP 值，按认证后的宽松上限解析。
//
// 返回值：
//   - raw 是这条值在连接上的原始字节，便于原样转发；
//   - args 仅在值是以 bulk/simple/整数元素构成的数组（或 inline 命令）时非空，
//     用于识别 AUTH/HELLO 这类需要代理介入的命令；
//   - 无法按命令解析的值（例如 RESP3 的 map、push）仍会完整返回 raw，args 为空。
func readCommand(r *bufio.Reader) (raw []byte, args []string, err error) {
	return readCommandLimit(r, relayLimits)
}

// readCommandLimit 按给定上限读取一条 RESP 值。超限立即返回错误，调用方应断开连接。
func readCommandLimit(r *bufio.Reader, lim readLimits) (raw []byte, args []string, err error) {
	first, err := r.ReadByte()
	if err != nil {
		return nil, nil, err
	}
	budget := &readBudget{lim: lim}
	if err := budget.add(1); err != nil {
		return nil, nil, err
	}
	switch first {
	case '*':
		line, err := readLineLimit(r, lim, budget)
		if err != nil {
			return nil, nil, err
		}
		n, convErr := strconv.Atoi(line)
		if convErr != nil || n < 0 {
			return nil, nil, fmt.Errorf("redisproxy: invalid array length %q", line)
		}
		if n > lim.maxArray {
			return nil, nil, fmt.Errorf("redisproxy: array of %d elements exceeds the limit of %d", n, lim.maxArray)
		}
		raw = append([]byte{'*'}, line...)
		raw = append(raw, '\r', '\n')
		args = make([]string, 0, n)
		okArgs := true
		for i := 0; i < n; i++ {
			eb, err := r.ReadByte()
			if err != nil {
				return nil, nil, err
			}
			if err := budget.add(1); err != nil {
				return nil, nil, err
			}
			switch eb {
			case '$':
				elen, body, err := readBulkLimit(r, lim, budget, "bulk")
				if err != nil {
					return nil, nil, err
				}
				raw = append(raw, '$')
				raw = append(raw, elen...)
				raw = append(raw, '\r', '\n')
				raw = append(raw, body...)
				args = append(args, string(trimCRLF(body)))
			case '+', ':', '-', ',':
				val, err := readLineLimit(r, lim, budget)
				if err != nil {
					return nil, nil, err
				}
				raw = append(raw, eb)
				raw = append(raw, val...)
				raw = append(raw, '\r', '\n')
				args = append(args, val)
			default:
				okArgs = false
				// 未知元素类型：把剩余数组元素按通用 RESP 值读掉，仅保留 raw。
				rest, err := readValueRaw(r, eb, 1, lim, budget)
				if err != nil {
					return nil, nil, err
				}
				raw = append(raw, eb)
				raw = append(raw, rest...)
			}
		}
		if !okArgs {
			args = nil
		}
		return raw, args, nil
	case '+', '-', ':', ',', '$', '=', '%', '~', '#', '_', '(', '!', '>', '|':
		rest, err := readValueRaw(r, first, 0, lim, budget)
		if err != nil {
			return nil, nil, err
		}
		raw = append([]byte{first}, rest...)
		return raw, nil, nil
	default:
		// inline 命令：整行按空白切分。
		line, err := readLineWithFirstLimit(r, first, lim, budget)
		if err != nil {
			return nil, nil, err
		}
		fields := strings.Fields(line)
		raw = append([]byte(line), '\r', '\n')
		return raw, fields, nil
	}
}

// readBulkLimit 读取一个 bulk 的长度行与内容（含结尾 CRLF），返回长度行原文与内容。
func readBulkLimit(r *bufio.Reader, lim readLimits, budget *readBudget, what string) ([]byte, []byte, error) {
	line, err := readLineLimit(r, lim, budget)
	if err != nil {
		return nil, nil, err
	}
	size, convErr := strconv.Atoi(line)
	if convErr != nil || size < 0 {
		return nil, nil, fmt.Errorf("redisproxy: invalid %s length %q", what, line)
	}
	if size > lim.maxBulk {
		return nil, nil, fmt.Errorf("redisproxy: %s of %d bytes exceeds the limit of %d", what, size, lim.maxBulk)
	}
	if err := budget.add(size + 2); err != nil {
		return nil, nil, err
	}
	body := make([]byte, size+2)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, nil, err
	}
	return []byte(line), body, nil
}

// readValueRaw 读掉首字节之后的其余部分，返回不含首字节的原始字节。
// 容器类型不额外追加 CRLF：每个元素自身已经带上了完整编码。
func readValueRaw(r *bufio.Reader, first byte, depth int, lim readLimits, budget *readBudget) ([]byte, error) {
	switch first {
	case '$', '=':
		line, body, err := readBulkLimit(r, lim, budget, "bulk")
		if err != nil {
			return nil, err
		}
		out := append(line, '\r', '\n')
		return append(out, body...), nil
	case '!':
		_, body, err := readBulkLimit(r, lim, budget, "blob error")
		if err != nil {
			return nil, err
		}
		return body, nil
	case '*', '~', '>':
		return readAggregate(r, first, depth, lim, budget, 1)
	case '%', '|':
		return readAggregate(r, first, depth, lim, budget, 2)
	case '+', '-', ':', '_', ',', '#', '(':
		line, err := readLineLimit(r, lim, budget)
		if err != nil {
			return nil, err
		}
		out := append([]byte(line), '\r', '\n')
		return out, nil
	}
	return nil, errors.New("redisproxy: unsupported RESP type")
}

// readAggregate 读取数组/集合/push/map 的元素。
// factor 是元素个数的倍数（map 的长度行是键值对数，实际元素数为 2 倍）。
func readAggregate(r *bufio.Reader, first byte, depth int, lim readLimits, budget *readBudget, factor int) ([]byte, error) {
	if depth >= lim.maxDepth {
		return nil, fmt.Errorf("redisproxy: aggregate nesting exceeds the limit of %d", lim.maxDepth)
	}
	line, err := readLineLimit(r, lim, budget)
	if err != nil {
		return nil, err
	}
	n, convErr := strconv.Atoi(line)
	if convErr != nil || n < 0 {
		return nil, fmt.Errorf("redisproxy: invalid aggregate length %q", line)
	}
	if n*factor > lim.maxArray {
		return nil, fmt.Errorf("redisproxy: aggregate of %d elements exceeds the limit of %d", n*factor, lim.maxArray)
	}
	out := append([]byte(line), '\r', '\n')
	for i := 0; i < n*factor; i++ {
		nb, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if err := budget.add(1); err != nil {
			return nil, err
		}
		sub, err := readValueRaw(r, nb, depth+1, lim, budget)
		if err != nil {
			return nil, err
		}
		out = append(out, nb)
		out = append(out, sub...)
	}
	return out, nil
}

func readLineLimit(r *bufio.Reader, lim readLimits, budget *readBudget) (string, error) {
	var b []byte
	for {
		chunk, err := r.ReadSlice('\n')
		b = append(b, chunk...)
		if len(b) > lim.maxLine {
			return "", fmt.Errorf("redisproxy: line exceeds the limit of %d bytes", lim.maxLine)
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return "", err
	}
	if budget != nil {
		if err := budget.add(len(b)); err != nil {
			return "", err
		}
	}
	line := strings.TrimSuffix(string(b), "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

func readLineWithFirstLimit(r *bufio.Reader, first byte, lim readLimits, budget *readBudget) (string, error) {
	rest, err := readLineLimit(r, lim, budget)
	if err != nil {
		return "", err
	}
	return string(first) + rest, nil
}

// trimCRLF 去掉 bulk 内容尾部的 CRLF。
func trimCRLF(b []byte) []byte {
	if len(b) >= 2 && b[len(b)-2] == '\r' && b[len(b)-1] == '\n' {
		return b[:len(b)-2]
	}
	return b
}

// encodeCommand 把命令重新编码为 RESP2 数组。
func encodeCommand(args []string) []byte {
	var b strings.Builder
	b.WriteString("*")
	b.WriteString(strconv.Itoa(len(args)))
	b.WriteString("\r\n")
	for _, a := range args {
		b.WriteString("$")
		b.WriteString(strconv.Itoa(len(a)))
		b.WriteString("\r\n")
		b.WriteString(a)
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

// simpleString 返回 RESP simple string。
func simpleString(s string) []byte { return []byte("+" + s + "\r\n") }

// errorString 返回 RESP error。参数不得包含秘密。
func errorString(s string) []byte { return []byte("-" + sanitizeLine(s) + "\r\n") }

// sanitizeLine 把换行替换掉，避免构造出畸形 RESP。
func sanitizeLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// readReply 读取上游的一条完整回复原始字节（用于 AUTH 判定）。
func readReply(r *bufio.Reader) ([]byte, error) {
	first, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	budget := &readBudget{lim: relayLimits}
	rest, err := readValueRaw(r, first, 0, relayLimits, budget)
	if err != nil {
		return nil, err
	}
	out := append([]byte{first}, rest...)
	return out, nil
}
