package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tamamo/tamamo/internal/config"
)

func TestCommands(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TAMAMO_TARGET", "")
	mgr, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := mgr.Stored()

	if err := runCommand(dir, true, true); err != nil {
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
	if err := runCommand(dir, true, false); err != nil {
		t.Fatalf("-check rejected a valid tamamo.yaml: %v", err)
	}

	// -check reports a broken file and leaves it alone.
	bad := []byte("rules:\n  - name: x\n    action: maybe\n")
	settings := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(settings, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runCommand(dir, true, false); err == nil {
		t.Fatal("-check accepted an invalid tamamo.yaml")
	}
	if got, _ := os.ReadFile(settings); string(got) != string(bad) {
		t.Fatal("-check rewrote tamamo.yaml")
	}
}
