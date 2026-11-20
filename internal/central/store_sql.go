package central

import (
	"context"
	"database/sql"
	"time"
)

// schema 是中心的最小表结构。许可表额外记录主体，供撤销与审计对账。
const schema = `
CREATE TABLE IF NOT EXISTS central_meta (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	epoch TEXT NOT NULL,
	signing_key BYTEA NOT NULL,
	created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	secret_hash TEXT NOT NULL,
	status TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS leases (
	id TEXT PRIMARY KEY,
	device_id TEXT NOT NULL,
	binding_id TEXT NOT NULL,
	credential_version INTEGER NOT NULL,
	mode TEXT NOT NULL,
	epoch TEXT NOT NULL,
	issued_at TIMESTAMPTZ NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL,
	status TEXT NOT NULL,
	principal_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS revocations (
	sequence BIGSERIAL PRIMARY KEY,
	at TIMESTAMPTZ NOT NULL,
	kind TEXT NOT NULL,
	target TEXT NOT NULL,
	epoch TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS binding_policy (
	binding_id TEXT PRIMARY KEY,
	principal_id TEXT NOT NULL DEFAULT '',
	credential_id TEXT NOT NULL,
	credential_version INTEGER NOT NULL,
	mode TEXT NOT NULL,
	status TEXT NOT NULL
);
`

// migrations 让已有的中心库补上许可与策略主体列；重复执行安全。
// 旧策略的空主体只兼容旧版空主体请求，不作为跨主体通配。
const migrations = `
ALTER TABLE leases ADD COLUMN IF NOT EXISTS principal_id TEXT NOT NULL DEFAULT '';
ALTER TABLE binding_policy ADD COLUMN IF NOT EXISTS principal_id TEXT NOT NULL DEFAULT '';
`

// sqlData 是 dataStore 的 PostgreSQL 实现。
type sqlData struct {
	db *sql.DB
}

func (d sqlData) RegisterDevice(ctx context.Context, id, name, secretHash string, at time.Time) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO devices(id, name, secret_hash, status, created_at) VALUES($1,$2,$3,$4,$5)`,
		id, name, secretHash, "active", at)
	return err
}

func (d sqlData) Device(ctx context.Context, id string) (string, string, error) {
	var secretHash, status string
	err := d.db.QueryRowContext(ctx, `SELECT secret_hash, status FROM devices WHERE id=$1`, id).Scan(&secretHash, &status)
	return secretHash, status, err
}

func (d sqlData) DeviceStatus(ctx context.Context, id string) (string, error) {
	var status string
	err := d.db.QueryRowContext(ctx, `SELECT status FROM devices WHERE id=$1`, id).Scan(&status)
	return status, err
}

func (d sqlData) UpsertPolicy(ctx context.Context, bindingID string, p policyRecord) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO binding_policy(binding_id, principal_id, credential_id, credential_version, mode, status) VALUES($1,$2,$3,$4,$5, 'active')
		ON CONFLICT(binding_id) DO UPDATE SET principal_id=excluded.principal_id, credential_id=excluded.credential_id, credential_version=excluded.credential_version, mode=excluded.mode, status='active'`,
		bindingID, p.PrincipalID, p.CredentialID, p.CredentialVersion, p.Mode)
	return err
}

func (d sqlData) Policy(ctx context.Context, bindingID string) (policyRecord, error) {
	var p policyRecord
	err := d.db.QueryRowContext(ctx, `SELECT principal_id, credential_id, credential_version, mode, status FROM binding_policy WHERE binding_id=$1`, bindingID).
		Scan(&p.PrincipalID, &p.CredentialID, &p.CredentialVersion, &p.Mode, &p.Status)
	return p, err
}

func (d sqlData) BindingStatus(ctx context.Context, bindingID string) (string, error) {
	var status string
	err := d.db.QueryRowContext(ctx, `SELECT status FROM binding_policy WHERE binding_id=$1`, bindingID).Scan(&status)
	return status, err
}

func (d sqlData) InsertLease(ctx context.Context, l Lease) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO leases(id, device_id, binding_id, credential_version, mode, epoch, issued_at, expires_at, status, principal_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		l.ID, l.DeviceID, l.BindingID, l.CredentialVersion, l.Mode, l.Epoch, l.IssuedAt, l.ExpiresAt, "active", l.PrincipalID)
	return err
}

func (d sqlData) Lease(ctx context.Context, leaseID, deviceID string) (leaseRecord, error) {
	var rec leaseRecord
	err := d.db.QueryRowContext(ctx, `SELECT epoch, status, binding_id, principal_id, mode, credential_version, expires_at FROM leases WHERE id=$1 AND device_id=$2`,
		leaseID, deviceID).
		Scan(&rec.Epoch, &rec.Status, &rec.BindingID, &rec.PrincipalID, &rec.Mode, &rec.CredentialVersion, &rec.ExpiresAt)
	return rec, err
}

func (d sqlData) RevokeDevice(ctx context.Context, target string, at time.Time, epoch string) error {
	if _, err := d.db.ExecContext(ctx, `UPDATE devices SET status='revoked' WHERE id=$1`, target); err != nil {
		return err
	}
	_, err := d.db.ExecContext(ctx, `INSERT INTO revocations(at, kind, target, epoch) VALUES($1,$2,$3,$4)`, at, "device", target, epoch)
	return err
}

func (d sqlData) RevokeBinding(ctx context.Context, target string, at time.Time, epoch string) error {
	if _, err := d.db.ExecContext(ctx, `UPDATE binding_policy SET status='revoked' WHERE binding_id=$1`, target); err != nil {
		return err
	}
	_, err := d.db.ExecContext(ctx, `INSERT INTO revocations(at, kind, target, epoch) VALUES($1,$2,$3,$4)`, at, "binding", target, epoch)
	return err
}

func (d sqlData) CountRevocations(ctx context.Context, epoch, deviceID, bindingID string) (int, error) {
	var n int
	err := d.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM revocations WHERE epoch=$1 AND ((kind='device' AND target=$2) OR (kind='binding' AND target=$3))`,
		epoch, deviceID, bindingID).Scan(&n)
	return n, err
}

func (d sqlData) Events(ctx context.Context, since int64) ([]Revocation, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT sequence, at, kind, target, epoch FROM revocations WHERE sequence > $1 ORDER BY sequence`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Revocation
	for rows.Next() {
		var rev Revocation
		if err := rows.Scan(&rev.Sequence, &rev.At, &rev.Kind, &rev.Target, &rev.Epoch); err != nil {
			continue
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}
