package integration

import (
	"fmt"
	"os"
	"strings"
)

// iniDocument 是保留原始行序的最小 INI 文档，用于只改受管键。
type iniDocument struct {
	lines []string
}

// parseINI 读取文件内容为行列表。文件不存在时返回空文档。
func parseINI(path string) (*iniDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &iniDocument{}, nil
		}
		return nil, err
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	// 末尾换行会制造空尾行，保留它以维持格式。
	return &iniDocument{lines: lines}, nil
}

func (d *iniDocument) String() string { return strings.Join(d.lines, "\n") }

// sectionRange 返回 section 的行范围（不含节头行）。
func (d *iniDocument) sectionRange(section string) (start, end int, ok bool) {
	in := false
	for i, line := range d.lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"))
			if in {
				return start, i, true
			}
			if name == section {
				in = true
				start = i + 1
			}
		}
	}
	if in {
		return start, len(d.lines), true
	}
	return 0, 0, false
}

// splitKey 把 "key = value" 拆成键与值，"=" 两侧与行尾空白都忽略。
func splitKey(line string) (key, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "[") {
		return "", "", false
	}
	i := strings.IndexByte(trimmed, '=')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(trimmed[:i]), strings.TrimSpace(trimmed[i+1:]), true
}

// value 返回 section 中某个键的值。
func (d *iniDocument) value(section, key string) (string, bool) {
	start, end, ok := d.sectionRange(section)
	if !ok {
		return "", false
	}
	for _, line := range d.lines[start:end] {
		k, v, ok := splitKey(line)
		if ok && strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

// setValue 只替换或插入目标键，保留其它行与注释。
func (d *iniDocument) setValue(section, key, value string) {
	start, end, ok := d.sectionRange(section)
	if !ok {
		if len(d.lines) > 0 && d.lines[len(d.lines)-1] != "" {
			d.lines = append(d.lines, "")
		}
		d.lines = append(d.lines, "["+section+"]", key+" = "+value)
		return
	}
	for i := start; i < end; i++ {
		k, _, ok := splitKey(d.lines[i])
		if ok && strings.EqualFold(k, key) {
			d.lines[i] = key + " = " + value
			return
		}
	}
	// 插到本节的最后一个非空行之后。
	insertAt := end
	for insertAt > start && strings.TrimSpace(d.lines[insertAt-1]) == "" {
		insertAt--
	}
	d.lines = append(d.lines[:insertAt], append([]string{key + " = " + value}, d.lines[insertAt:]...)...)
}

// removeValue 删除目标键，保留其余内容。
func (d *iniDocument) removeValue(section, key string) bool {
	start, end, ok := d.sectionRange(section)
	if !ok {
		return false
	}
	removed := false
	out := make([]string, 0, len(d.lines))
	for i, line := range d.lines {
		if i >= start && i < end {
			if k, _, ok := splitKey(line); ok && strings.EqualFold(k, key) {
				removed = true
				continue
			}
		}
		out = append(out, line)
	}
	d.lines = out
	return removed
}

func (d *iniDocument) empty() bool {
	return strings.TrimSpace(d.String()) == ""
}

func (d *iniDocument) validate() error {
	if d.empty() {
		return fmt.Errorf("config document is empty")
	}
	return nil
}
