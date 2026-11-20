// Package secret 提供秘密值的专用封装。
//
// 约束：秘密不参与默认 JSON 序列化与日志格式化；需要真实值时显式调用 Reveal，
// 每次 Reveal 返回副本，调用方负责缩短副本生存期。
package secret

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
)

// Value 是只可显式读取的秘密字符串。
type Value struct {
	b []byte
}

// New 用字符串构造秘密值。
func New(s string) Value {
	b := make([]byte, len(s))
	copy(b, s)
	return Value{b: b}
}

// FromBytes 复制字节构造秘密值。
func FromBytes(b []byte) Value {
	cp := make([]byte, len(b))
	copy(cp, b)
	return Value{b: cp}
}

// Empty 是空秘密值。
var Empty = Value{}

// Reveal 返回秘密副本。调用方不得记录、持久化或跨进程传递。
func (v Value) Reveal() []byte {
	cp := make([]byte, len(v.b))
	copy(cp, v.b)
	return cp
}

// RevealString 返回秘密字符串副本。
func (v Value) RevealString() string { return string(v.b) }

// Len 返回秘密字节长度。
func (v Value) Len() int { return len(v.b) }

// IsEmpty 报告秘密是否为空。
func (v Value) IsEmpty() bool { return len(v.b) == 0 }

// Clear 尽力清除本副本内容。
func (v *Value) Clear() {
	for i := range v.b {
		v.b[i] = 0
	}
	v.b = nil
}

// String 永远返回占位符，避免被日志格式化。
func (v Value) String() string { return "<redacted>" }

// GoString 供 %#v 使用。
func (v Value) GoString() string { return "<redacted>" }

// Format 覆盖所有格式化动词，只输出占位符。
func (v Value) Format(f fmt.State, verb rune) {
	_, _ = f.Write([]byte("<redacted>"))
}

// MarshalJSON 只输出占位符。秘密需要落库时走加密路径，不经过普通 JSON。
func (v Value) MarshalJSON() ([]byte, error) {
	return json.Marshal("<redacted>")
}

// UnmarshalJSON 拒绝从普通 JSON 恢复秘密，防止绕过加密层。
func (v *Value) UnmarshalJSON([]byte) error {
	return fmt.Errorf("secret: plaintext secrets cannot be unmarshaled from JSON")
}

// Equal 用常量时间比较两个秘密。
func (v Value) Equal(other Value) bool {
	if len(v.b) != len(other.b) {
		return false
	}
	return subtle.ConstantTimeCompare(v.b, other.b) == 1
}

// EqualString 用常量时间与普通字符串比较，供受控通道校验使用。
func (v Value) EqualString(s string) bool {
	return subtle.ConstantTimeCompare(v.b, []byte(s)) == 1
}
