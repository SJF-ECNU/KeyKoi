package daemon

import (
	"context"
	"debug/macho"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"keykoi/internal/model"
	"keykoi/internal/osruntime"
	"keykoi/internal/store"
)

type ipcPeerKey struct{}

type authorizationSubject struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Label string `json:"label"`
	paths []string
}

type agentRegistration struct {
	Kind       string `json:"kind,omitempty"`
	Key        string `json:"key"`
	Label      string `json:"label"`
	Executable string `json:"executable"`
}

var agentKey = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func (d *Daemon) builtinSubjects() []authorizationSubject {
	label := strings.TrimSpace(d.cfg.UserLabel)
	if label == "" {
		label = "我的账户"
		if u, err := user.Current(); err == nil {
			label += " · " + u.Username
		}
	}
	localID := localPrincipalID()
	home, _ := os.UserHomeDir()
	return []authorizationSubject{
		{ID: localID, Key: "me", Label: label},
		{ID: localID + "_codex_app", Key: "codex-app", Label: "Codex App", paths: []string{
			"/Applications/Codex.app/Contents/MacOS/Codex",
			"/Applications/Codex.app/Contents/MacOS/codex",
			"/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex",
		}},
		{ID: localID + "_codex_cli", Key: "codex-cli", Label: "Codex CLI", paths: installedPaths(
			"/opt/homebrew/bin/codex", "/usr/local/bin/codex",
		)},
		{ID: localID + "_claude_code", Key: "claude-code", Label: "Claude Code", paths: installedPaths(
			"/opt/homebrew/bin/claude", "/usr/local/bin/claude", filepath.Join(home, ".local/bin/claude"),
		)},
	}
}

func installedPaths(links ...string) []string {
	var paths []string
	for _, link := range links {
		if filepath.IsAbs(link) {
			if path, err := filepath.EvalSymlinks(link); err == nil {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func (d *Daemon) subjects(ctx context.Context) ([]authorizationSubject, error) {
	subjects := d.builtinSubjects()
	principals, err := d.store.ListPrincipals(ctx)
	if err != nil {
		return nil, err
	}
	for _, principal := range principals {
		if principal.IdentityType != "local_agent" || principal.Status != model.StatusActive {
			continue
		}
		var reg agentRegistration
		if json.Unmarshal([]byte(principal.IdentityReference), &reg) == nil && reg.Kind == "native_executable" && reg.Executable != "" {
			subjects = append(subjects, authorizationSubject{
				ID: principal.ID, Key: reg.Key, Label: reg.Label, paths: []string{reg.Executable},
			})
		}
	}
	return subjects, nil
}

func (d *Daemon) currentSubject(r *http.Request) (authorizationSubject, error) {
	subjects, err := d.subjects(r.Context())
	if err != nil {
		return authorizationSubject{}, err
	}
	peer, _ := r.Context().Value(ipcPeerKey{}).(net.Conn)
	for _, path := range osruntime.ProcessExecutables(peer) {
		for _, subject := range subjects[1:] {
			for _, candidate := range subject.paths {
				if path != candidate {
					continue
				}
				return subject, nil
			}
		}
	}
	return subjects[0], nil
}

func (d *Daemon) handleSubjects(w http.ResponseWriter, r *http.Request) {
	if _, err := d.requireAdmin(r); err != nil {
		writeAPIError(w, err)
		return
	}
	switch r.Method {
	case http.MethodGet:
		subjects, err := d.subjects(r.Context())
		if err != nil {
			writeAPIError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"subjects": subjects})
	case http.MethodPost:
		d.registerAgent(w, r)
	default:
		writeAPIError(w, model.NewError("", "method not allowed"))
	}
}

func (d *Daemon) handleCurrentSubject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, model.NewError("", "method not allowed"))
		return
	}
	subject, err := d.currentSubject(r)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, subject)
}

func (d *Daemon) registerAgent(w http.ResponseWriter, r *http.Request) {
	var reg agentRegistration
	if err := decodeJSON(r, &reg); err != nil {
		writeAPIError(w, err)
		return
	}
	if reg.Kind == "" {
		reg.Kind = "native_executable"
	}
	if reg.Kind != "native_executable" {
		writeAPIError(w, model.NewError("", "unsupported agent identification kind"))
		return
	}
	reg.Label = strings.TrimSpace(reg.Label)
	if !agentKey.MatchString(reg.Key) || reg.Label == "" || len(reg.Label) > 128 {
		writeAPIError(w, model.NewError("", "use a lowercase agent key and a display name"))
		return
	}
	resolved := installedPaths(reg.Executable)
	if len(resolved) != 1 || !nativeExecutable(resolved[0]) {
		writeAPIError(w, model.NewError("", "agent executable must be an absolute path to a native macOS executable"))
		return
	}
	reg.Executable = resolved[0]
	d.mu.Lock()
	defer d.mu.Unlock()
	subjects, err := d.subjects(r.Context())
	if err != nil {
		writeAPIError(w, err)
		return
	}
	for _, subject := range subjects {
		if subject.Key == reg.Key {
			writeAPIError(w, model.NewError(model.CodeConfigDrift, "agent key already registered"))
			return
		}
		for _, path := range subject.paths {
			if path == reg.Executable {
				writeAPIError(w, model.NewError(model.CodeConfigDrift, "executable already registered"))
				return
			}
		}
	}
	subject := authorizationSubject{ID: localPrincipalID() + "_agent_" + reg.Key, Key: reg.Key, Label: reg.Label}
	if _, err := d.store.GetPrincipal(r.Context(), subject.ID); err == nil {
		writeAPIError(w, model.NewError(model.CodeConfigDrift, "agent key already registered"))
		return
	}
	ref, err := json.Marshal(reg)
	if err != nil {
		writeAPIError(w, err)
		return
	}
	principal := &store.Principal{ID: subject.ID, IdentityType: "local_agent", IdentityReference: string(ref), Status: model.StatusActive}
	if err := d.store.PutPrincipal(r.Context(), principal); err != nil {
		writeAPIError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, subject)
}

func nativeExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return false
	}
	if binary, err := macho.Open(path); err == nil {
		defer binary.Close()
		return binary.Type == macho.TypeExec
	}
	if fat, err := macho.OpenFat(path); err == nil {
		defer fat.Close()
		return len(fat.Arches) > 0 && fat.Arches[0].Type == macho.TypeExec
	}
	return false
}
