package mongoproxy

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MongoDB wire protocol 常量。
const (
	opMsg        int32 = 2013
	opReply      int32 = 1
	opQuery      int32 = 2004
	opCompressed int32 = 2012

	flagChecksumPresent uint32 = 0x1
	flagMoreToCome      uint32 = 0x2

	maxMessageSize = 48 << 20
)

// message 是读到的一条 wire protocol 消息（OP_MSG）。
type message struct {
	raw        []byte
	requestID  int32
	responseTo int32
	opCode     int32
	flags      uint32
	body       []byte
	// legacy 表示这是旧式 OP_QUERY 握手，回复必须用 OP_REPLY。
	legacy bool
}

// readMessage 读取一条完整消息并按 OP_MSG 解析出命令文档。
func readMessage(r *bufio.Reader) (*message, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := int(int32(binary.LittleEndian.Uint32(hdr[0:4])))
	if length < 16 || length > maxMessageSize {
		return nil, fmt.Errorf("mongoproxy: invalid message length %d", length)
	}
	rest := make([]byte, length-16)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	raw := append(append([]byte(nil), hdr[:]...), rest...)
	m := &message{
		raw:        raw,
		requestID:  int32(binary.LittleEndian.Uint32(hdr[4:8])),
		responseTo: int32(binary.LittleEndian.Uint32(hdr[8:12])),
		opCode:     int32(binary.LittleEndian.Uint32(hdr[12:16])),
	}
	switch m.opCode {
	case opCompressed:
		return nil, errors.New("mongoproxy: compressed messages are not supported")
	case opQuery:
		if err := m.parseLegacyQuery(rest); err != nil {
			return nil, err
		}
		return m, nil
	case opMsg:
	default:
		return nil, fmt.Errorf("mongoproxy: unsupported opcode %d (OP_MSG and OP_QUERY are supported)", m.opCode)
	}
	if len(rest) < 5 {
		return nil, errors.New("mongoproxy: truncated OP_MSG")
	}
	m.flags = binary.LittleEndian.Uint32(rest[0:4])
	sections := rest[4:]
	if m.flags&flagChecksumPresent != 0 {
		if len(sections) < 4 {
			return nil, errors.New("mongoproxy: truncated OP_MSG checksum")
		}
		sections = sections[:len(sections)-4]
	}
	for len(sections) > 0 {
		kind := sections[0]
		sections = sections[1:]
		switch kind {
		case 0:
			if len(sections) < 5 {
				return nil, errors.New("mongoproxy: truncated OP_MSG body")
			}
			n := int(int32(binary.LittleEndian.Uint32(sections[:4])))
			if n < 5 || n > len(sections) {
				return nil, errors.New("mongoproxy: invalid OP_MSG body length")
			}
			if m.body == nil {
				m.body = append([]byte(nil), sections[:n]...)
			}
			sections = sections[n:]
		case 1:
			if len(sections) < 4 {
				return nil, errors.New("mongoproxy: truncated document sequence")
			}
			n := int(int32(binary.LittleEndian.Uint32(sections[:4])))
			if n < 5 || n > len(sections) {
				return nil, errors.New("mongoproxy: invalid document sequence length")
			}
			sections = sections[n:]
		default:
			return nil, fmt.Errorf("mongoproxy: unknown OP_MSG section kind %d", kind)
		}
	}
	if m.body == nil {
		return nil, errors.New("mongoproxy: OP_MSG has no body section")
	}
	return m, nil
}

// parseLegacyQuery 解析 OP_QUERY（只用于旧式握手）。
// 布局：flags(int32) + 完整集合名(cstring) + numberToSkip(int32) + numberToReturn(int32) + 查询文档。
func (m *message) parseLegacyQuery(rest []byte) error {
	if len(rest) < 4 {
		return errors.New("mongoproxy: truncated OP_QUERY")
	}
	rest = rest[4:]
	_, rest, ok := cutCString(rest)
	if !ok {
		return errors.New("mongoproxy: truncated OP_QUERY namespace")
	}
	if len(rest) < 8 {
		return errors.New("mongoproxy: truncated OP_QUERY header")
	}
	rest = rest[8:]
	if len(rest) < 5 {
		return errors.New("mongoproxy: truncated OP_QUERY document")
	}
	n := int(int32(binary.LittleEndian.Uint32(rest[:4])))
	if n < 5 || n > len(rest) {
		return errors.New("mongoproxy: invalid OP_QUERY document length")
	}
	m.body = append([]byte(nil), rest[:n]...)
	m.legacy = true
	return nil
}

// command 解码命令文档。
func (m *message) command() (map[string]any, error) {
	return document(m.body)
}

// writeOPMsg 写出一条 OP_MSG 回复。section kind 0 的字节是 OP_MSG 必需的。
func writeOPMsg(w io.Writer, requestID, responseTo int32, body []byte) error {
	length := 16 + 4 + 1 + len(body)
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(length))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(requestID))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(opMsg))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	var flags [5]byte
	if _, err := w.Write(flags[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// writeOPReply 写出旧式 OP_REPLY，用于回应客户端的 OP_QUERY 握手。
func writeOPReply(w io.Writer, requestID, responseTo int32, body []byte) error {
	const fixed = 16 + 4 + 8 + 4 + 4
	length := fixed + len(body)
	var hdr [fixed]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(length))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(requestID))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(opReply))
	// responseFlags=0, cursorID=0, startingFrom=0, numberReturned=1
	binary.LittleEndian.PutUint32(hdr[16:20], 0)
	binary.LittleEndian.PutUint64(hdr[20:28], 0)
	binary.LittleEndian.PutUint32(hdr[28:32], 0)
	binary.LittleEndian.PutUint32(hdr[32:36], 1)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// commandName 返回命令文档的第一个键（MongoDB 的命令名约定）。
// 命令是 BSON 文档的第一个字段，map 会丢失顺序，所以从原始字节扫描。
func commandName(body []byte) (string, error) {
	if len(body) < 6 {
		return "", errors.New("mongoproxy: bson body too short")
	}
	name, _, ok := cutCString(body[5:])
	if !ok {
		return "", errors.New("mongoproxy: truncated bson command name")
	}
	return name, nil
}
