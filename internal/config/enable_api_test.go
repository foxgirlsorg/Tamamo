package config

import "testing"

func TestAdminAPIFollowsTamamoEnableAPI(t *testing.T) {
	for v, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true, "YES": true, "on": true} {
		t.Setenv("TAMAMO_ENABLE_API", v)
		m, err := Load(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if got := m.Get().Admin.Enabled; got != want {
			t.Errorf("TAMAMO_ENABLE_API=%q: admin API on = %v, want %v", v, got, want)
		}
	}
	// Files from before TAMAMO_ENABLE_API may still say admin.enabled; it is ignored.
	if _, err := ParseConfigYAML([]byte("admin:\n  enabled: true\n")); err != nil {
		t.Fatal(err)
	}
}
