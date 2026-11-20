package daemon

import (
	"context"
	"errors"
	"testing"

	"keykoi/internal/broker"
	"keykoi/internal/model"
	"keykoi/internal/oauth"
	"keykoi/internal/secret"
	"keykoi/internal/store"
)

// 生产路径上的 OAuth 提交必须是原子 CAS：revision 已变时一个字节都不写。
func TestOAuthStoreCommitCASUsesBackendCAS(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	src := broker.NewMemorySource()
	backend := NewMemoryBackend(st, src)
	d := New(Config{DataDir: t.TempDir()}, st, backend)
	adapter := oauthStore{d: d}

	creds := &model.Credential{ID: "cred_oauth", Kind: model.KindOAuth, Label: "o", CurrentVersion: 1, Status: model.StatusActive}
	if err := st.CreateCredential(ctx, creds); err != nil {
		t.Fatal(err)
	}
	first := model.CredentialVersion{CredentialID: "cred_oauth", Version: 1, Fields: map[string]secret.Value{"access_token": secret.New("a")}}
	if _, err := adapter.CommitCAS(ctx, "cred_oauth", 1, first); err != nil {
		t.Fatalf("first CAS commit must succeed: %v", err)
	}
	updated, err := st.GetCredential(ctx, "cred_oauth")
	if err != nil {
		t.Fatal(err)
	}
	if updated.CurrentVersion != 2 || updated.Revision != 2 {
		t.Fatalf("after CAS commit version=%d revision=%d, want 2/2", updated.CurrentVersion, updated.Revision)
	}

	second := model.CredentialVersion{CredentialID: "cred_oauth", Version: 2, Fields: map[string]secret.Value{"access_token": secret.New("b")}}
	if _, err := adapter.CommitCAS(ctx, "cred_oauth", 1, second); err == nil {
		t.Fatal("a stale revision must be refused")
	} else if !errors.Is(err, oauth.ErrCommitConflict) {
		t.Fatalf("expected oauth.ErrCommitConflict, got %v", err)
	}
	after, err := st.GetCredential(ctx, "cred_oauth")
	if err != nil {
		t.Fatal(err)
	}
	if after.CurrentVersion != 2 || after.Revision != 2 {
		t.Fatalf("refused CAS must not write: version=%d revision=%d", after.CurrentVersion, after.Revision)
	}
}
