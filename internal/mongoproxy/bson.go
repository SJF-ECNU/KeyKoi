package mongoproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// BSON 类型常量（只覆盖代理需要读写的子集）。
const (
	bsonDouble     byte = 0x01
	bsonString     byte = 0x02
	bsonDocument   byte = 0x03
	bsonArray      byte = 0x04
	bsonBinary     byte = 0x05
	bsonUndefined  byte = 0x06
	bsonObjectID   byte = 0x07
	bsonBool       byte = 0x08
	bsonDateTime   byte = 0x09
	bsonNull       byte = 0x0A
	bsonRegex      byte = 0x0B
	bsonDBPointer  byte = 0x0C
	bsonCode       byte = 0x0D
	bsonSymbol     byte = 0x0E
	bsonCodeWithWS byte = 0x0F
	bsonInt32      byte = 0x10
	bsonTimestamp  byte = 0x11
	bsonInt64      byte = 0x12
	bsonDecimal128 byte = 0x13
	bsonMinKey     byte = 0xFF
	bsonMaxKey     byte = 0x7F
)

// bsonBuilder 构造 BSON 文档。
type bsonBuilder struct {
	b []byte
}

func newBson() *bsonBuilder {
	return &bsonBuilder{b: make([]byte, 4)}
}

func (d *bsonBuilder) elem(typ byte, name string) {
	d.b = append(d.b, typ)
	d.b = append(d.b, name...)
	d.b = append(d.b, 0)
}

// Int32 追加一个 int32 字段。
func (d *bsonBuilder) Int32(name string, v int32) *bsonBuilder {
	d.elem(bsonInt32, name)
	d.b = binary.LittleEndian.AppendUint32(d.b, uint32(v))
	return d
}

// Int64 追加一个 int64 字段。
func (d *bsonBuilder) Int64(name string, v int64) *bsonBuilder {
	d.elem(bsonInt64, name)
	d.b = binary.LittleEndian.AppendUint64(d.b, uint64(v))
	return d
}

// Double 追加一个 double 字段。
func (d *bsonBuilder) Double(name string, v float64) *bsonBuilder {
	d.elem(bsonDouble, name)
	d.b = binary.LittleEndian.AppendUint64(d.b, math.Float64bits(v))
	return d
}

// Bool 追加一个 bool 字段。
func (d *bsonBuilder) Bool(name string, v bool) *bsonBuilder {
	d.elem(bsonBool, name)
	if v {
		d.b = append(d.b, 1)
	} else {
		d.b = append(d.b, 0)
	}
	return d
}

// String 追加一个 string 字段。
func (d *bsonBuilder) String(name, v string) *bsonBuilder {
	d.elem(bsonString, name)
	d.b = binary.LittleEndian.AppendUint32(d.b, uint32(len(v)+1))
	d.b = append(d.b, v...)
	d.b = append(d.b, 0)
	return d
}

// Binary 追加一个 binary 字段。
func (d *bsonBuilder) Binary(name string, subtype byte, data []byte) *bsonBuilder {
	d.elem(bsonBinary, name)
	d.b = binary.LittleEndian.AppendUint32(d.b, uint32(len(data)))
	d.b = append(d.b, subtype)
	d.b = append(d.b, data...)
	return d
}

// DateTime 追加一个 UTC datetime 字段（毫秒）。
func (d *bsonBuilder) DateTime(name string, ms int64) *bsonBuilder {
	d.elem(bsonDateTime, name)
	d.b = binary.LittleEndian.AppendUint64(d.b, uint64(ms))
	return d
}

// Document 追加一个嵌套文档字段。
func (d *bsonBuilder) Document(name string, inner []byte) *bsonBuilder {
	d.elem(bsonDocument, name)
	d.b = append(d.b, inner...)
	return d
}

// Array 追加一个数组字段。
func (d *bsonBuilder) Array(name string, inner []byte) *bsonBuilder {
	d.elem(bsonArray, name)
	d.b = append(d.b, inner...)
	return d
}

// Finish 结束文档，写入总长度与结尾 NUL。
func (d *bsonBuilder) Finish() []byte {
	binary.LittleEndian.PutUint32(d.b[:4], uint32(len(d.b)+1))
	d.b = append(d.b, 0)
	return d.b
}

// document 解码 BSON 文档为键值对。值类型：float64、string、[]byte、bool、
// int32、int64、map[string]any、[]any、time.Time 的毫秒整数。
func document(b []byte) (map[string]any, error) {
	out := map[string]any{}
	if len(b) < 5 {
		return nil, errors.New("mongoproxy: bson document too short")
	}
	total := int(int32(binary.LittleEndian.Uint32(b[:4])))
	if total != len(b) || total < 5 {
		return nil, fmt.Errorf("mongoproxy: bson length mismatch (declared %d, actual %d)", total, len(b))
	}
	rest := b[4 : len(b)-1]
	for len(rest) > 0 {
		typ := rest[0]
		rest = rest[1:]
		name, r, ok := cutCString(rest)
		if !ok {
			return nil, errors.New("mongoproxy: truncated bson field name")
		}
		rest = r
		val, r, err := parseValue(typ, rest)
		if err != nil {
			return nil, err
		}
		rest = r
		out[name] = val
	}
	return out, nil
}

func parseValue(typ byte, b []byte) (any, []byte, error) {
	switch typ {
	case bsonDouble:
		if len(b) < 8 {
			return nil, nil, errors.New("mongoproxy: truncated double")
		}
		return math.Float64frombits(binary.LittleEndian.Uint64(b[:8])), b[8:], nil
	case bsonString:
		v, rest, err := parseString(b)
		return v, rest, err
	case bsonDocument:
		if len(b) < 4 {
			return nil, nil, errors.New("mongoproxy: truncated nested document")
		}
		n := int(int32(binary.LittleEndian.Uint32(b[:4])))
		if n < 5 || n > len(b) {
			return nil, nil, errors.New("mongoproxy: invalid nested document length")
		}
		doc, err := document(b[:n])
		return doc, b[n:], err
	case bsonArray:
		if len(b) < 4 {
			return nil, nil, errors.New("mongoproxy: truncated array")
		}
		n := int(int32(binary.LittleEndian.Uint32(b[:4])))
		if n < 5 || n > len(b) {
			return nil, nil, errors.New("mongoproxy: invalid array length")
		}
		doc, err := document(b[:n])
		if err != nil {
			return nil, nil, err
		}
		arr := make([]any, 0, len(doc))
		for i := 0; ; i++ {
			v, ok := doc[fmt.Sprintf("%d", i)]
			if !ok {
				break
			}
			arr = append(arr, v)
		}
		return arr, b[n:], nil
	case bsonBinary:
		if len(b) < 5 {
			return nil, nil, errors.New("mongoproxy: truncated binary")
		}
		n := int(int32(binary.LittleEndian.Uint32(b[:4])))
		if n < 0 || 5+n > len(b) {
			return nil, nil, errors.New("mongoproxy: invalid binary length")
		}
		subtype := b[4]
		data := append([]byte(nil), b[5:5+n]...)
		return binaryValue{subtype: subtype, data: data}, b[5+n:], nil
	case bsonUndefined, bsonNull, bsonMinKey, bsonMaxKey:
		return nil, b, nil
	case bsonObjectID:
		if len(b) < 12 {
			return nil, nil, errors.New("mongoproxy: truncated objectid")
		}
		return append([]byte(nil), b[:12]...), b[12:], nil
	case bsonBool:
		if len(b) < 1 {
			return nil, nil, errors.New("mongoproxy: truncated bool")
		}
		return b[0] != 0, b[1:], nil
	case bsonDateTime, bsonTimestamp, bsonInt64:
		if len(b) < 8 {
			return nil, nil, errors.New("mongoproxy: truncated int64")
		}
		return int64(binary.LittleEndian.Uint64(b[:8])), b[8:], nil
	case bsonInt32:
		if len(b) < 4 {
			return nil, nil, errors.New("mongoproxy: truncated int32")
		}
		return int32(binary.LittleEndian.Uint32(b[:4])), b[4:], nil
	case bsonDecimal128:
		if len(b) < 16 {
			return nil, nil, errors.New("mongoproxy: truncated decimal128")
		}
		return append([]byte(nil), b[:16]...), b[16:], nil
	case bsonRegex:
		_, rest, ok := cutCString(b)
		if !ok {
			return nil, nil, errors.New("mongoproxy: truncated regex")
		}
		_, rest, ok = cutCString(rest)
		if !ok {
			return nil, nil, errors.New("mongoproxy: truncated regex options")
		}
		return "<regex>", rest, nil
	case bsonCode, bsonSymbol:
		v, rest, err := parseString(b)
		return v, rest, err
	case bsonCodeWithWS:
		if len(b) < 4 {
			return nil, nil, errors.New("mongoproxy: truncated code_w_s")
		}
		rest := b[4:]
		_, rest, err := parseString(rest)
		if err != nil {
			return nil, nil, err
		}
		doc, rest, err := parseValue(bsonDocument, rest)
		return doc, rest, err
	case bsonDBPointer:
		v, rest, err := parseString(b)
		if err != nil {
			return nil, nil, err
		}
		if len(rest) < 12 {
			return nil, nil, errors.New("mongoproxy: truncated dbpointer")
		}
		return v, rest[12:], nil
	}
	return nil, nil, fmt.Errorf("mongoproxy: unsupported bson type %#x", typ)
}

type binaryValue struct {
	subtype byte
	data    []byte
}

func parseString(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, errors.New("mongoproxy: truncated string")
	}
	n := int(int32(binary.LittleEndian.Uint32(b[:4])))
	if n < 1 || 4+n > len(b) {
		return "", nil, errors.New("mongoproxy: invalid string length")
	}
	return string(b[4 : 4+n-1]), b[4+n:], nil
}

func cutCString(b []byte) (string, []byte, bool) {
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", nil, false
}

// bsonInt 把解码出的数值统一成 int64。
func bsonInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	}
	return 0, false
}

// bsonStringValue 取字符串字段。
func bsonStringValue(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// bsonBinaryValue 取 binary 字段内容。
func bsonBinaryValue(v any) ([]byte, bool) {
	b, ok := v.(binaryValue)
	if !ok {
		return nil, false
	}
	return b.data, true
}
