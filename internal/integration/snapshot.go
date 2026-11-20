package integration

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"keykoi/internal/store"
)

// snapshotKeySize 是本地快照密钥长度（AES-256）。
const snapshotKeySize = 32

// fieldSnapshot 是接入前受管字段的原始值。
//
// 只保存本次受管的 section 与 key，不保存整份配置：这样其他账号、其他 section
// 以及既有助手设置都不会被复制到新的备份文件里，也不会在撤销时被覆盖。
type fieldSnapshot struct {
	Section string `json:"section"`
	Key     string `json:"key"`
	Value   string `json:"value"`
	Existed bool   `json:"existed"`
}

// snapshotDir 是快照与本地密钥目录。
func (m *Manager) snapshotDir() string {
	return filepath.Join(m.DataDir, "integrations")
}

// snapshotPath 返回某个接入的加密快照路径。
func (m *Manager) snapshotPath(id string) string {
	return filepath.Join(m.snapshotDir(), id+".snapshot.enc")
}

// snapshotExists 判断某个接入是否已经有加密快照。
func (m *Manager) snapshotExists(id string) bool {
	if m.DataDir == "" {
		return false
	}
	_, err := os.Stat(m.snapshotPath(id))
	return err == nil
}

// snapshotKey 读取或创建本地快照密钥（0600）。
func (m *Manager) snapshotKey() ([]byte, error) {
	dir := m.snapshotDir()
	path := filepath.Join(dir, "snapshot.key")
	if data, err := os.ReadFile(path); err == nil && len(data) == snapshotKeySize {
		return data, nil
	}
	key := make([]byte, snapshotKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// writeSnapshot 加密保存受管字段的原始值，并把路径记入接入记录。
// DataDir 未配置（未启用恢复材料）时不做任何事。
func (m *Manager) writeSnapshot(rec *store.IntegrationRecord, snap fieldSnapshot) error {
	if m.DataDir == "" {
		rec.BackupPath = ""
		return nil
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	key, err := m.snapshotKey()
	if err != nil {
		return err
	}
	sealed, err := sealSnapshot(key, rec.ID, raw)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.snapshotDir(), 0o700); err != nil {
		return err
	}
	path := m.snapshotPath(rec.ID)
	if err := writeFileAtomic(path, sealed); err != nil {
		return err
	}
	rec.BackupPath = path
	return nil
}

// readSnapshot 读取并解密受管字段快照。没有快照时返回 os.ErrNotExist。
func (m *Manager) readSnapshot(rec *store.IntegrationRecord) (fieldSnapshot, error) {
	if rec.BackupPath == "" {
		return fieldSnapshot{}, os.ErrNotExist
	}
	sealed, err := os.ReadFile(rec.BackupPath)
	if err != nil {
		return fieldSnapshot{}, err
	}
	key, err := m.snapshotKey()
	if err != nil {
		return fieldSnapshot{}, err
	}
	raw, err := openSnapshot(key, rec.ID, sealed)
	if err != nil {
		return fieldSnapshot{}, fmt.Errorf("recovery snapshot %s cannot be decrypted: %w", rec.BackupPath, err)
	}
	var snap fieldSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fieldSnapshot{}, fmt.Errorf("recovery snapshot %s is malformed: %w", rec.BackupPath, err)
	}
	return snap, nil
}

// removeSnapshot 在撤销完成后删除加密快照与本地密钥引用。
func (m *Manager) removeSnapshot(rec *store.IntegrationRecord) {
	if rec.BackupPath != "" {
		_ = os.Remove(rec.BackupPath)
	}
}

// sealSnapshot 用 AES-256-GCM 加密快照，附加数据绑定接入 ID。
func sealSnapshot(key []byte, id string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte(id)), nil
}

// openSnapshot 解密快照。
func openSnapshot(key []byte, id string, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("snapshot is truncated")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, []byte(id))
}
