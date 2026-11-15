package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/foxgirlsorg/tamamo/internal/admin"
	"github.com/foxgirlsorg/tamamo/internal/config"
)

func TestEnvLogin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TAMAMO_TARGET", "")
	t.Setenv("TAMAMO_ADMIN_USERNAME", "operator")
	t.Setenv("TAMAMO_ADMIN_PASSWORD", "correct horse battery")
	mgr, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyEnvLogin(mgr); err != nil {
		t.Fatal(err)
	}
	st := mgr.Stored()
	if st.Admin.Username != "operator" || !admin.VerifyPassword(st.Admin.PasswordHash, "correct horse battery") {
		t.Fatalf("login not stored: %+v", st.Admin)
	}
	if mgr.Locked()["admin.login"] != "TAMAMO_ADMIN_USERNAME" {
		t.Fatalf("login not locked: %v", mgr.Locked())
	}
	// Unchanged login: the stored hash stays as it is.
	if err := applyEnvLogin(mgr); err != nil {
		t.Fatal(err)
	}
	if mgr.Stored().Admin.PasswordHash != st.Admin.PasswordHash {
		t.Fatal("hash rewritten although the login did not change")
	}

	t.Setenv("TAMAMO_ADMIN_PASSWORD", "")
	if err := applyEnvLogin(mgr); err == nil {
		t.Fatal("username without password accepted")
	}
	t.Setenv("TAMAMO_ADMIN_PASSWORD", "short")
	if err := applyEnvLogin(mgr); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestCommands(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TAMAMO_TARGET", "")
	t.Setenv("TAMAMO_ADMIN_PASSWORD", "another long password")
	if err := runCommand(dir, false, "admin", false); err != nil {
		t.Fatal(err)
	}
	mgr, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := mgr.Stored()
	if before.Admin.Username != "admin" || !admin.VerifyPassword(before.Admin.PasswordHash, "another long password") {
		t.Fatalf("-set-login: %+v", before.Admin)
	}

	if err := runCommand(dir, true, "", true); err != nil {
		t.Fatal(err)
	}
	mgr, err = config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if mgr.Stored().Secret == before.Secret {
		t.Fatal("-rotate-secret kept the old secret")
	}

	// -check accepts the settings file the running instance wrote.
	if err := runCommand(dir, true, "", false); err != nil {
		t.Fatalf("-check rejected a valid tamamo.yaml: %v", err)
	}

	// -check reports a broken file and leaves it alone.
	bad := []byte("rules:\n  - name: x\n    action: maybe\n")
	settings := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(settings, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCommand(dir, true, "", false); err == nil {
		t.Fatal("-check accepted an invalid tamamo.yaml")
	}
	if got, _ := os.ReadFile(settings); string(got) != string(bad) {
		t.Fatal("-check rewrote tamamo.yaml")
	}
}
