package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"keykoi/internal/model"
)

// SQLite 是单机持久存储。敏感字段在写入前已由 vault 加密，这里只保存密文。
type SQLite struct {
	db   *sql.DB
	path string
}

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_meta (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	schema_version INTEGER NOT NULL,
	crypto_version INTEGER NOT NULL,
	kdf_algorithm TEXT NOT NULL,
	kdf_salt BLOB NOT NULL,
	kdf_time INTEGER NOT NULL,
	kdf_memory_kib INTEGER NOT NULL,
	kdf_threads INTEGER NOT NULL,
	wrapped_root_key BLOB NOT NULL,
	wrap_nonce BLOB NOT NULL,
	root_check BLOB,
	root_check_nonce BLOB,
	authorization_epoch TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	label TEXT NOT NULL,
	current_version INTEGER NOT NULL,
	status TEXT NOT NULL,
	revision INTEGER NOT NULL,
	provider_expires_at TEXT
);
CREATE TABLE IF NOT EXISTS credential_versions (
	credential_id TEXT NOT NULL,
	version INTEGER NOT NULL,
	ciphertext BLOB NOT NULL,
	nonce BLOB NOT NULL,
	wrapped_dek BLOB NOT NULL,
	wrap_nonce BLOB NOT NULL,
	crypto_version INTEGER NOT NULL,
	provider_expires_at TEXT,
	created_at TEXT NOT NULL,
	PRIMARY KEY (credential_id, version),
	FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS bindings (
	id TEXT PRIMARY KEY,
	credential_id TEXT NOT NULL,
	upstream_origin TEXT NOT NULL,
	allowed_paths TEXT NOT NULL,
	auth_scheme TEXT NOT NULL,
	auth_header TEXT NOT NULL,
	token_field TEXT NOT NULL,
	username_field TEXT NOT NULL,
	password_field TEXT NOT NULL,
	adapter_id TEXT NOT NULL,
	route TEXT NOT NULL,
	status TEXT NOT NULL,
	revision INTEGER NOT NULL,
	FOREIGN KEY (credential_id) REFERENCES credentials(id)
);
CREATE TABLE IF NOT EXISTS principals (
	id TEXT PRIMARY KEY,
	identity_type TEXT NOT NULL,
	identity_reference TEXT NOT NULL,
	status TEXT NOT NULL,
	admin INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS grants (
	id TEXT PRIMARY KEY,
	principal_id TEXT NOT NULL,
	binding_id TEXT NOT NULL,
	delivery_mode TEXT NOT NULL,
	max_lease_seconds INTEGER NOT NULL,
	auth_requirement TEXT NOT NULL DEFAULT 'once',
	status TEXT NOT NULL,
	revision INTEGER NOT NULL,
	FOREIGN KEY (principal_id) REFERENCES principals(id),
	FOREIGN KEY (binding_id) REFERENCES bindings(id)
);
CREATE TABLE IF NOT EXISTS adapter_profiles (
	id TEXT PRIMARY KEY,
	adapter_version INTEGER NOT NULL,
	manifest TEXT NOT NULL,
	status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS installations (
	id TEXT PRIMARY KEY,
	absolute_executable TEXT NOT NULL,
	tool_version TEXT NOT NULL,
	os TEXT NOT NULL,
	ownership_status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS integrations (
	id TEXT PRIMARY KEY,
	profile_id TEXT NOT NULL,
	tool_version TEXT NOT NULL,
	os TEXT NOT NULL,
	mechanism TEXT NOT NULL DEFAULT '',
	config_path TEXT NOT NULL DEFAULT '',
	section TEXT NOT NULL DEFAULT '',
	managed_key TEXT NOT NULL DEFAULT '',
	config_fingerprint TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL,
	verified_version TEXT NOT NULL DEFAULT '',
	backup_path TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_events (
	event_id TEXT PRIMARY KEY,
	time TEXT NOT NULL,
	principal_id TEXT NOT NULL,
	session_id TEXT NOT NULL,
	binding_id TEXT NOT NULL,
	credential_id TEXT NOT NULL,
	credential_version INTEGER NOT NULL,
	mode TEXT NOT NULL,
	result TEXT NOT NULL,
	error_code TEXT NOT NULL,
	duration_ms INTEGER NOT NULL,
	detail TEXT NOT NULL,
	auth_method TEXT NOT NULL DEFAULT 'none',
	auth_result TEXT NOT NULL DEFAULT 'not_required'
);
CREATE TABLE IF NOT EXISTS migration_snapshots (
	integration_id TEXT PRIMARY KEY,
	encrypted_snapshot BLOB NOT NULL,
	created_at TEXT NOT NULL
);
`

// OpenSQLite 打开或创建密钥库数据库。数据库目录以 0700 创建。
func OpenSQLite(path string) (*SQLite, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("prepare database directory: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(FULL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(sqliteSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	// 数据库、WAL 与共享内存文件都必须只对当前用户可读。
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			if err := os.Chmod(p, 0o600); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("restrict permissions on %s: %w", p, err)
			}
		}
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(1, ?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		_ = db.Close()
		return nil, err
	}
	// 旧库升级：ALTER TABLE 补齐授权策略与审计验证字段，旧行取安全默认值。
	for _, col := range []struct{ table, name, ddl string }{
		{"grants", "auth_requirement", `ALTER TABLE grants ADD COLUMN auth_requirement TEXT NOT NULL DEFAULT 'once'`},
		{"audit_events", "auth_method", `ALTER TABLE audit_events ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'none'`},
		{"audit_events", "auth_result", `ALTER TABLE audit_events ADD COLUMN auth_result TEXT NOT NULL DEFAULT 'not_required'`},
		{"vault_meta", "root_check", `ALTER TABLE vault_meta ADD COLUMN root_check BLOB`},
		{"vault_meta", "root_check_nonce", `ALTER TABLE vault_meta ADD COLUMN root_check_nonce BLOB`},
	} {
		if err := ensureColumn(db, col.table, col.name, col.ddl); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("migrate %s.%s: %w", col.table, col.name, err)
		}
	}
	// 老库可能已有重复有效授权。保留 revision/rowid 最新的一条，其余撤销后再建立部分唯一索引。
	if _, err := db.Exec(`UPDATE grants SET status='revoked', revision=revision+1
		WHERE status='active' AND EXISTS (
			SELECT 1 FROM grants newer
			WHERE newer.principal_id=grants.principal_id AND newer.binding_id=grants.binding_id
				AND newer.delivery_mode=grants.delivery_mode AND newer.status='active'
				AND (newer.revision>grants.revision OR (newer.revision=grants.revision AND newer.rowid>grants.rowid))
		)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("converge duplicate active grants: %w", err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS grants_one_active_per_use
		ON grants(principal_id, binding_id, delivery_mode) WHERE status='active'`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create active grant uniqueness index: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(2, ?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLite{db: db, path: path}, nil
}

// ensureColumn 在列缺失时执行 ALTER TABLE，使旧库无需重建即可继续使用。
func ensureColumn(db *sql.DB, table, column, ddl string) error {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if found {
		return nil
	}
	if _, err := db.Exec(ddl); err != nil {
		return err
	}
	return nil
}

// Path 返回数据库文件路径。
func (s *SQLite) Path() string { return s.path }

// Close 关闭数据库。
func (s *SQLite) Close() error { return s.db.Close() }

// DB 暴露底层连接，供测试执行只读检查。
func (s *SQLite) DB() *sql.DB { return s.db }

func (s *SQLite) VaultMeta(ctx context.Context) (*VaultMeta, error) {
	row := s.db.QueryRowContext(ctx, `SELECT schema_version, crypto_version, kdf_algorithm, kdf_salt, kdf_time, kdf_memory_kib, kdf_threads, wrapped_root_key, wrap_nonce, root_check, root_check_nonce, authorization_epoch, created_at FROM vault_meta WHERE id=1`)
	m := &VaultMeta{}
	var created string
	if err := row.Scan(&m.SchemaVersion, &m.CryptoVersion, &m.KDFAlgorithm, &m.KDFSalt, &m.KDFTime, &m.KDFMemoryKiB, &m.KDFThreads, &m.WrappedRootKey, &m.WrapNonce, &m.RootCheck, &m.RootCheckNonce, &m.AuthorizationEpoch, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	m.CreatedAt, _ = time.Parse(time.RFC3339, created)
	return m, nil
}

func (s *SQLite) PutVaultMeta(ctx context.Context, meta *VaultMeta) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO vault_meta(id, schema_version, crypto_version, kdf_algorithm, kdf_salt, kdf_time, kdf_memory_kib, kdf_threads, wrapped_root_key, wrap_nonce, root_check, root_check_nonce, authorization_epoch, created_at)
		VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET schema_version=excluded.schema_version, crypto_version=excluded.crypto_version, kdf_algorithm=excluded.kdf_algorithm, kdf_salt=excluded.kdf_salt, kdf_time=excluded.kdf_time, kdf_memory_kib=excluded.kdf_memory_kib, kdf_threads=excluded.kdf_threads, wrapped_root_key=excluded.wrapped_root_key, wrap_nonce=excluded.wrap_nonce, root_check=excluded.root_check, root_check_nonce=excluded.root_check_nonce, authorization_epoch=excluded.authorization_epoch`,
		meta.SchemaVersion, meta.CryptoVersion, meta.KDFAlgorithm, meta.KDFSalt, meta.KDFTime, meta.KDFMemoryKiB, meta.KDFThreads, meta.WrappedRootKey, meta.WrapNonce, nullableBytes(meta.RootCheck), nullableBytes(meta.RootCheckNonce), meta.AuthorizationEpoch, meta.CreatedAt.UTC().Format(time.RFC3339))
	return err
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseNullTime(v sql.NullString) *time.Time {
	if !v.Valid || v.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, v.String)
	if err != nil {
		return nil
	}
	return &t
}

func (s *SQLite) CreateCredential(ctx context.Context, c *model.Credential) error {
	rev := c.Revision
	if rev == 0 {
		rev = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO credentials(id, kind, label, current_version, status, revision, provider_expires_at) VALUES(?,?,?,?,?,?,?)`,
		c.ID, c.Kind, c.Label, c.CurrentVersion, c.Status, rev, nullTime(c.ProviderExpiresAt))
	if err != nil {
		return fmt.Errorf("insert credential: %w", err)
	}
	c.Revision = rev
	return nil
}

func (s *SQLite) CreateCredentialWithVersion(ctx context.Context, c *model.Credential, rec *VersionRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rev := c.Revision
	if rev == 0 {
		rev = 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO credentials(id, kind, label, current_version, status, revision, provider_expires_at) VALUES(?,?,?,?,?,?,?)`,
		c.ID, c.Kind, c.Label, c.CurrentVersion, c.Status, rev, nullTime(c.ProviderExpiresAt)); err != nil {
		return fmt.Errorf("insert credential: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO credential_versions(credential_id, version, ciphertext, nonce, wrapped_dek, wrap_nonce, crypto_version, provider_expires_at, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		rec.CredentialID, rec.Version, rec.Ciphertext, rec.Nonce, rec.WrappedDEK, rec.WrapNonce, rec.CryptoVersion, nullTime(rec.ProviderExpiresAt), rec.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("insert version: %w", err)
	}
	c.Revision = rev
	return tx.Commit()
}

func (s *SQLite) ReplaceVault(ctx context.Context, meta *VaultMeta, creds []*model.Credential, versions []*VersionRecord, bindings []*model.Binding, principals []*Principal, grants []*model.Grant) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// 恢复只保留备份内的记录：审计与接入状态都随备份/恢复口径一起清空，
	// 避免出现「审计已清空但仍显示上一套库的接入记录」。
	for _, stmt := range []string{
		`DELETE FROM audit_events`, `DELETE FROM migration_snapshots`, `DELETE FROM integrations`,
		`DELETE FROM grants`, `DELETE FROM bindings`, `DELETE FROM credential_versions`,
		`DELETE FROM credentials`, `DELETE FROM principals`, `DELETE FROM vault_meta`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vault_meta(id, schema_version, crypto_version, kdf_algorithm, kdf_salt, kdf_time, kdf_memory_kib, kdf_threads, wrapped_root_key, wrap_nonce, root_check, root_check_nonce, authorization_epoch, created_at) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		meta.SchemaVersion, meta.CryptoVersion, meta.KDFAlgorithm, meta.KDFSalt, meta.KDFTime, meta.KDFMemoryKiB, meta.KDFThreads, meta.WrappedRootKey, meta.WrapNonce, nullableBytes(meta.RootCheck), nullableBytes(meta.RootCheckNonce), meta.AuthorizationEpoch, meta.CreatedAt.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	for _, c := range creds {
		if _, err := tx.ExecContext(ctx, `INSERT INTO credentials(id, kind, label, current_version, status, revision, provider_expires_at) VALUES(?,?,?,?,?,?,?)`,
			c.ID, c.Kind, c.Label, c.CurrentVersion, c.Status, c.Revision, nullTime(c.ProviderExpiresAt)); err != nil {
			return err
		}
	}
	for _, v := range versions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO credential_versions(credential_id, version, ciphertext, nonce, wrapped_dek, wrap_nonce, crypto_version, provider_expires_at, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			v.CredentialID, v.Version, v.Ciphertext, v.Nonce, v.WrappedDEK, v.WrapNonce, v.CryptoVersion, nullTime(v.ProviderExpiresAt), v.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	for _, p := range principals {
		if _, err := tx.ExecContext(ctx, `INSERT INTO principals(id, identity_type, identity_reference, status, admin) VALUES(?,?,?,?,?)`,
			p.ID, p.IdentityType, p.IdentityReference, p.Status, boolInt(p.Admin)); err != nil {
			return err
		}
	}
	for _, b := range bindings {
		if _, err := tx.ExecContext(ctx, `INSERT INTO bindings(id, credential_id, upstream_origin, allowed_paths, auth_scheme, auth_header, token_field, username_field, password_field, adapter_id, route, status, revision) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			b.ID, b.CredentialID, b.UpstreamOrigin, joinPaths(b.AllowedPaths), b.AuthScheme, b.AuthHeader, b.TokenField, b.UsernameField, b.PasswordField, b.AdapterID, b.Route, b.Status, b.Revision); err != nil {
			return err
		}
	}
	for _, g := range grants {
		if _, err := tx.ExecContext(ctx, `INSERT INTO grants(id, principal_id, binding_id, delivery_mode, max_lease_seconds, auth_requirement, status, revision) VALUES(?,?,?,?,?,?,?,?)`,
			g.ID, g.PrincipalID, g.BindingID, g.DeliveryMode, int64(g.MaxLeaseDuration.Seconds()), authRequirement(g), g.Status, g.Revision); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SQLite) GetCredential(ctx context.Context, id string) (*model.Credential, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, kind, label, current_version, status, revision, provider_expires_at FROM credentials WHERE id=?`, id)
	return scanCredential(row)
}

type scanner interface{ Scan(dest ...any) error }

func scanCredential(row scanner) (*model.Credential, error) {
	c := &model.Credential{}
	var pexp sql.NullString
	if err := row.Scan(&c.ID, &c.Kind, &c.Label, &c.CurrentVersion, &c.Status, &c.Revision, &pexp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	c.ProviderExpiresAt = parseNullTime(pexp)
	return c, nil
}

func (s *SQLite) ListCredentials(ctx context.Context) ([]*model.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, label, current_version, status, revision, provider_expires_at FROM credentials ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateCredentialStatus(ctx context.Context, id string, status model.EntityStatus, revision int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE credentials SET status=?, revision=revision+1 WHERE id=? AND (?=0 OR revision=?)`, status, id, revision, revision)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *SQLite) UpdateProviderExpiry(ctx context.Context, id string, expires *time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE credentials SET provider_expires_at=? WHERE id=?`, nullTime(expires), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) PutVersion(ctx context.Context, rec *VersionRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO credential_versions(credential_id, version, ciphertext, nonce, wrapped_dek, wrap_nonce, crypto_version, provider_expires_at, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		rec.CredentialID, rec.Version, rec.Ciphertext, rec.Nonce, rec.WrappedDEK, rec.WrapNonce, rec.CryptoVersion, nullTime(rec.ProviderExpiresAt), rec.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("insert version: %w", err)
	}
	return nil
}

func (s *SQLite) GetVersion(ctx context.Context, credentialID string, version int) (*VersionRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT credential_id, version, ciphertext, nonce, wrapped_dek, wrap_nonce, crypto_version, provider_expires_at, created_at FROM credential_versions WHERE credential_id=? AND version=?`, credentialID, version)
	return scanVersion(row)
}

func scanVersion(row scanner) (*VersionRecord, error) {
	rec := &VersionRecord{}
	var pexp sql.NullString
	var created string
	if err := row.Scan(&rec.CredentialID, &rec.Version, &rec.Ciphertext, &rec.Nonce, &rec.WrappedDEK, &rec.WrapNonce, &rec.CryptoVersion, &pexp, &created); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	rec.ProviderExpiresAt = parseNullTime(pexp)
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return rec, nil
}

func (s *SQLite) CurrentVersion(ctx context.Context, credentialID string) (*VersionRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT v.credential_id, v.version, v.ciphertext, v.nonce, v.wrapped_dek, v.wrap_nonce, v.crypto_version, v.provider_expires_at, v.created_at
		FROM credential_versions v JOIN credentials c ON c.id = v.credential_id AND c.current_version = v.version
		WHERE c.id=?`, credentialID)
	return scanVersion(row)
}

func (s *SQLite) SetCurrentVersion(ctx context.Context, credentialID string, version int, expectedRevision int64) (*model.Credential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM credential_versions WHERE credential_id=? AND version=?`, credentialID, version).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, ErrNotFound
	}
	res, err := tx.ExecContext(ctx, `UPDATE credentials SET current_version=?, revision=revision+1 WHERE id=? AND (?=0 OR revision=?)`, version, credentialID, expectedRevision, expectedRevision)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetCredential(ctx, credentialID)
}

// nullableBytes 把空切片写成 SQL NULL，避免旧库与导入备份出现零长度占位。
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// ActivateVersion 在一个事务内插入新版本、切换当前版本并写入原平台到期时间。
// 三步分开提交会在中断时留下未启用的版本，并让下一次轮换撞上相同版本号。
func (s *SQLite) ActivateVersion(ctx context.Context, credentialID string, rec *VersionRecord) (*model.Credential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO credential_versions(credential_id, version, ciphertext, nonce, wrapped_dek, wrap_nonce, crypto_version, provider_expires_at, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		rec.CredentialID, rec.Version, rec.Ciphertext, rec.Nonce, rec.WrappedDEK, rec.WrapNonce, rec.CryptoVersion, nullTime(rec.ProviderExpiresAt), rec.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, fmt.Errorf("insert version: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE credentials SET current_version=?, provider_expires_at=?, revision=revision+1 WHERE id=?`,
		rec.Version, nullTime(rec.ProviderExpiresAt), credentialID)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetCredential(ctx, credentialID)
}

// ActivateVersionCAS 只在 revision 未变时插入新版本并切换当前版本。
// 条件更新影响 0 行即表示记录已被并发修改，事务整体回滚。
func (s *SQLite) ActivateVersionCAS(ctx context.Context, credentialID string, rec *VersionRecord, expectedRevision int64) (*model.Credential, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT revision FROM credentials WHERE id=?`, credentialID).Scan(&revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if revision != expectedRevision {
		return nil, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO credential_versions(credential_id, version, ciphertext, nonce, wrapped_dek, wrap_nonce, crypto_version, provider_expires_at, created_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		rec.CredentialID, rec.Version, rec.Ciphertext, rec.Nonce, rec.WrappedDEK, rec.WrapNonce, rec.CryptoVersion, nullTime(rec.ProviderExpiresAt), rec.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return nil, fmt.Errorf("insert version: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE credentials SET current_version=?, provider_expires_at=?, revision=revision+1 WHERE id=? AND revision=?`,
		rec.Version, nullTime(rec.ProviderExpiresAt), credentialID, expectedRevision)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetCredential(ctx, credentialID)
}

func (s *SQLite) ListVersions(ctx context.Context, credentialID string) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM credential_versions WHERE credential_id=? ORDER BY version`, credentialID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteVersion(ctx context.Context, credentialID string, version int) error {
	var current int
	if err := s.db.QueryRowContext(ctx, `SELECT current_version FROM credentials WHERE id=?`, credentialID).Scan(&current); err != nil {
		return ErrNotFound
	}
	if current == version {
		return ErrConflict
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM credential_versions WHERE credential_id=? AND version=?`, credentialID, version)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) PutBinding(ctx context.Context, b *model.Binding) error {
	if b.Revision == 0 {
		b.Revision = 1
	}
	paths := joinPaths(b.AllowedPaths)
	_, err := s.db.ExecContext(ctx, `INSERT INTO bindings(id, credential_id, upstream_origin, allowed_paths, auth_scheme, auth_header, token_field, username_field, password_field, adapter_id, route, status, revision)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET credential_id=excluded.credential_id, upstream_origin=excluded.upstream_origin, allowed_paths=excluded.allowed_paths, auth_scheme=excluded.auth_scheme, auth_header=excluded.auth_header, token_field=excluded.token_field, username_field=excluded.username_field, password_field=excluded.password_field, adapter_id=excluded.adapter_id, route=excluded.route, status=excluded.status, revision=bindings.revision+1`,
		b.ID, b.CredentialID, b.UpstreamOrigin, paths, b.AuthScheme, b.AuthHeader, b.TokenField, b.UsernameField, b.PasswordField, b.AdapterID, b.Route, b.Status, b.Revision)
	return err
}

func (s *SQLite) GetBinding(ctx context.Context, id string) (*model.Binding, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, credential_id, upstream_origin, allowed_paths, auth_scheme, auth_header, token_field, username_field, password_field, adapter_id, route, status, revision FROM bindings WHERE id=?`, id)
	return scanBinding(row)
}

func (s *SQLite) GetBindingByRoute(ctx context.Context, route string) (*model.Binding, error) {
	// 历史数据可能留下同路由的多条绑定：优先有效状态，再按 id 排序，
	// 让选择结果与服务端唯一约束的意图一致且可复现。
	row := s.db.QueryRowContext(ctx, `SELECT id, credential_id, upstream_origin, allowed_paths, auth_scheme, auth_header, token_field, username_field, password_field, adapter_id, route, status, revision FROM bindings WHERE route=?
		ORDER BY CASE WHEN status='active' THEN 0 ELSE 1 END, id LIMIT 1`, route)
	return scanBinding(row)
}

func scanBinding(row scanner) (*model.Binding, error) {
	b := &model.Binding{}
	var paths string
	if err := row.Scan(&b.ID, &b.CredentialID, &b.UpstreamOrigin, &paths, &b.AuthScheme, &b.AuthHeader, &b.TokenField, &b.UsernameField, &b.PasswordField, &b.AdapterID, &b.Route, &b.Status, &b.Revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	b.AllowedPaths = splitPaths(paths)
	return b, nil
}

func (s *SQLite) ListBindings(ctx context.Context) ([]*model.Binding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, credential_id, upstream_origin, allowed_paths, auth_scheme, auth_header, token_field, username_field, password_field, adapter_id, route, status, revision FROM bindings ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Binding
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateBindingStatus(ctx context.Context, id string, status model.EntityStatus, revision int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE bindings SET status=?, revision=revision+1 WHERE id=? AND (?=0 OR revision=?)`, status, id, revision, revision)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *SQLite) PutIntegration(ctx context.Context, rec *IntegrationRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO integrations(id, profile_id, tool_version, os, mechanism, config_path, section, managed_key, config_fingerprint, state, verified_version, backup_path, detail)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET profile_id=excluded.profile_id, tool_version=excluded.tool_version, os=excluded.os, mechanism=excluded.mechanism, config_path=excluded.config_path, section=excluded.section, managed_key=excluded.managed_key, config_fingerprint=excluded.config_fingerprint, state=excluded.state, verified_version=excluded.verified_version, backup_path=excluded.backup_path, detail=excluded.detail`,
		rec.ID, rec.ProfileID, rec.ToolVersion, rec.OS, rec.Mechanism, rec.ConfigPath, rec.Section, rec.ManagedKey, rec.ManagedFingerprint, rec.State, rec.VerifiedVersion, rec.BackupPath, rec.Detail)
	return err
}

func (s *SQLite) GetIntegration(ctx context.Context, id string) (*IntegrationRecord, error) {
	rec := &IntegrationRecord{}
	err := s.db.QueryRowContext(ctx, `SELECT id, profile_id, tool_version, os, mechanism, config_path, section, managed_key, config_fingerprint, state, verified_version, backup_path, detail FROM integrations WHERE id=?`, id).
		Scan(&rec.ID, &rec.ProfileID, &rec.ToolVersion, &rec.OS, &rec.Mechanism, &rec.ConfigPath, &rec.Section, &rec.ManagedKey, &rec.ManagedFingerprint, &rec.State, &rec.VerifiedVersion, &rec.BackupPath, &rec.Detail)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *SQLite) ListIntegrations(ctx context.Context) ([]*IntegrationRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, profile_id, tool_version, os, mechanism, config_path, section, managed_key, config_fingerprint, state, verified_version, backup_path, detail FROM integrations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*IntegrationRecord
	for rows.Next() {
		rec := &IntegrationRecord{}
		if err := rows.Scan(&rec.ID, &rec.ProfileID, &rec.ToolVersion, &rec.OS, &rec.Mechanism, &rec.ConfigPath, &rec.Section, &rec.ManagedKey, &rec.ManagedFingerprint, &rec.State, &rec.VerifiedVersion, &rec.BackupPath, &rec.Detail); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteIntegration(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM integrations WHERE id=?`, id)
	return err
}

func (s *SQLite) PutPrincipal(ctx context.Context, p *Principal) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO principals(id, identity_type, identity_reference, status, admin) VALUES(?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET identity_type=excluded.identity_type, identity_reference=excluded.identity_reference, status=excluded.status, admin=excluded.admin`,
		p.ID, p.IdentityType, p.IdentityReference, p.Status, boolInt(p.Admin))
	return err
}

func (s *SQLite) GetPrincipal(ctx context.Context, id string) (*Principal, error) {
	p := &Principal{}
	var admin int
	err := s.db.QueryRowContext(ctx, `SELECT id, identity_type, identity_reference, status, admin FROM principals WHERE id=?`, id).
		Scan(&p.ID, &p.IdentityType, &p.IdentityReference, &p.Status, &admin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.Admin = admin != 0
	return p, nil
}

func (s *SQLite) ListPrincipals(ctx context.Context) ([]*Principal, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, identity_type, identity_reference, status, admin FROM principals ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Principal
	for rows.Next() {
		p := &Principal{}
		var admin int
		if err := rows.Scan(&p.ID, &p.IdentityType, &p.IdentityReference, &p.Status, &admin); err != nil {
			return nil, err
		}
		p.Admin = admin != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdatePrincipalStatus(ctx context.Context, id string, status model.EntityStatus) error {
	_, err := s.db.ExecContext(ctx, `UPDATE principals SET status=? WHERE id=?`, status, id)
	return err
}

func (s *SQLite) PutGrant(ctx context.Context, g *model.Grant) error {
	if g.Revision == 0 {
		g.Revision = 1
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if g.Status == model.StatusActive {
		// 新建与取代必须在同一事务中完成；唯一索引同时兜底阻止并发写入重复有效授权。
		if _, err := tx.ExecContext(ctx, `UPDATE grants SET status='revoked', revision=revision+1
			WHERE principal_id=? AND binding_id=? AND delivery_mode=? AND status='active' AND id<>?`,
			g.PrincipalID, g.BindingID, g.DeliveryMode, g.ID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO grants(id, principal_id, binding_id, delivery_mode, max_lease_seconds, auth_requirement, status, revision) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET principal_id=excluded.principal_id, binding_id=excluded.binding_id, delivery_mode=excluded.delivery_mode, max_lease_seconds=excluded.max_lease_seconds, auth_requirement=excluded.auth_requirement, status=excluded.status, revision=grants.revision+1`,
		g.ID, g.PrincipalID, g.BindingID, g.DeliveryMode, int64(g.MaxLeaseDuration.Seconds()), authRequirement(g), g.Status, g.Revision); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite) GetGrant(ctx context.Context, id string) (*model.Grant, error) {
	g := &model.Grant{}
	var secs int64
	var requirement string
	err := s.db.QueryRowContext(ctx, `SELECT id, principal_id, binding_id, delivery_mode, max_lease_seconds, auth_requirement, status, revision FROM grants WHERE id=?`, id).
		Scan(&g.ID, &g.PrincipalID, &g.BindingID, &g.DeliveryMode, &secs, &requirement, &g.Status, &g.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g.MaxLeaseDuration = time.Duration(secs) * time.Second
	g.AuthRequirement = requirement
	return g, nil
}

func (s *SQLite) ListGrants(ctx context.Context, principalID string) ([]*model.Grant, error) {
	q := `SELECT id, principal_id, binding_id, delivery_mode, max_lease_seconds, auth_requirement, status, revision FROM grants`
	var args []any
	if principalID != "" {
		q += ` WHERE principal_id=?`
		args = append(args, principalID)
	}
	q += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Grant
	for rows.Next() {
		g := &model.Grant{}
		var secs int64
		var requirement string
		if err := rows.Scan(&g.ID, &g.PrincipalID, &g.BindingID, &g.DeliveryMode, &secs, &requirement, &g.Status, &g.Revision); err != nil {
			return nil, err
		}
		g.MaxLeaseDuration = time.Duration(secs) * time.Second
		g.AuthRequirement = requirement
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateGrantStatus(ctx context.Context, id string, status model.EntityStatus, revision int64) error {
	// 条件更新与部分唯一索引共同保证 approve 不能复活已被取代的旧授权。
	res, err := s.db.ExecContext(ctx, `UPDATE grants SET status=?, revision=revision+1
		WHERE id=? AND (?=0 OR revision=?) AND (
			?<>'active' OR status='active' OR NOT EXISTS (
				SELECT 1 FROM grants other
				WHERE other.id<>grants.id AND other.principal_id=grants.principal_id
					AND other.binding_id=grants.binding_id AND other.delivery_mode=grants.delivery_mode
					AND other.status='active'
			)
		)`, status, id, revision, revision, status)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrConflict
	}
	return nil
}

func (s *SQLite) AppendAudit(ctx context.Context, e *AuditEvent) error {
	t := e.Time
	if t.IsZero() {
		t = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_events(event_id, time, principal_id, session_id, binding_id, credential_id, credential_version, mode, result, error_code, duration_ms, detail, auth_method, auth_result) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.ID, t.UTC().Format(time.RFC3339Nano), e.PrincipalID, e.SessionID, e.BindingID, e.CredentialID, e.CredentialVersion, e.Mode, e.Result, e.ErrorCode, e.DurationMS, e.Detail, auditAuthMethod(e), auditAuthResult(e))
	return err
}

func (s *SQLite) ListAudit(ctx context.Context, limit int) ([]*AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, time, principal_id, session_id, binding_id, credential_id, credential_version, mode, result, error_code, duration_ms, detail, auth_method, auth_result FROM audit_events ORDER BY time DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEvent
	for rows.Next() {
		e := &AuditEvent{}
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.PrincipalID, &e.SessionID, &e.BindingID, &e.CredentialID, &e.CredentialVersion, &e.Mode, &e.Result, &e.ErrorCode, &e.DurationMS, &e.Detail, &e.AuthMethod, &e.AuthResult); err != nil {
			return nil, err
		}
		e.Time, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// authRequirement 返回入库用的策略字符串；空值按默认 once 处理。
func authRequirement(g *model.Grant) string {
	if strings.TrimSpace(g.AuthRequirement) == "" {
		return model.DefaultAuthRequirement
	}
	return g.AuthRequirement
}

func auditAuthMethod(e *AuditEvent) string {
	if e.AuthMethod == "" {
		return "none"
	}
	return e.AuthMethod
}

func auditAuthResult(e *AuditEvent) string {
	if e.AuthResult == "" {
		return "not_required"
	}
	return e.AuthResult
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func joinPaths(paths []string) string {
	out := ""
	for i, p := range paths {
		if i > 0 {
			out += "\n"
		}
		out += p
	}
	return out
}

func splitPaths(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
