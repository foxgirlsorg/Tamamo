package config

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WatchInterval is how often Watch looks at the settings file.
const WatchInterval = 2 * time.Second

// Manager owns the settings file (tamamo.yaml), the signing key next to it
// and the effective (env-overridden) view of the settings.
type Manager struct {
	mu         sync.Mutex
	dir        string
	path       string // tamamo.yaml
	secretPath string // secret.key
	stored     *Config
	eff        atomic.Pointer[snapshot]
	locked     map[string]string
	subs       []func(*Config)
	renameSubs []func(map[string]string)

	file         fileState // what is on disk, as far as we know
	secretOnDisk string
}

// fileState is what we last saw of (or wrote to) one file.
type fileState struct {
	exists bool
	size   int64
	mtime  time.Time
	sum    [32]byte
}

func stateOf(path string, data []byte) fileState {
	st := fileState{exists: true, size: int64(len(data)), sum: sha256.Sum256(data)}
	if fi, err := os.Stat(path); err == nil {
		st.size, st.mtime = fi.Size(), fi.ModTime()
	}
	return st
}

func statNow(path string) fileState {
	b, err := os.ReadFile(path)
	if err != nil {
		return fileState{}
	}
	return stateOf(path, b)
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func newManager(dataDir string) *Manager {
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}
	return &Manager{
		dir:        dataDir,
		path:       filepath.Join(dataDir, FileName),
		secretPath: filepath.Join(dataDir, SecretFileName),
		locked:     map[string]string{},
	}
}

type diskRead struct {
	cfg   *Config
	found bool // tamamo.yaml exists
	data  []byte
}

// readDisk reads tamamo.yaml, or returns the defaults when there is none
// yet. It does not validate.
func (m *Manager) readDisk() (*diskRead, error) {
	b, err := os.ReadFile(m.path)
	switch {
	case err == nil:
		cfg, err := ParseConfigYAML(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.path, err)
		}
		return &diskRead{cfg: cfg, found: true, data: b}, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	return &diskRead{cfg: Defaults()}, nil
}

func readSecret(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Check reads and validates the settings in dataDir without writing anything.
func Check(dataDir string) error {
	m := newManager(dataDir)
	d, err := m.readDisk()
	if err != nil {
		return err
	}
	d.cfg.Secret = "check"
	if err := d.cfg.Validate(); err != nil {
		return fmt.Errorf("%s: %w", m.path, err)
	}
	m.stored = d.cfg
	return m.publish()
}

// Load reads dataDir/tamamo.yaml, creating it with defaults on first start.
func Load(dataDir string) (*Manager, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	m := newManager(dataDir)
	d, err := m.readDisk()
	if err != nil {
		return nil, err
	}
	cfg := d.cfg
	if !d.found {
		// First start: seed a few settings from the environment.
		if v := os.Getenv("TAMAMO_DIFFICULTY"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Protection.Difficulty = n
			}
		}
	}
	if s := readSecret(m.secretPath); s != "" {
		cfg.Secret = s
		m.secretOnDisk = s
	} else if cfg.Secret == "" {
		cfg.Secret = newSecret()
	}
	for _, o := range envOverrides {
		if v, ok := os.LookupEnv(o.env); ok && v != "" {
			m.locked[o.key] = o.env
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", m.path, err)
	}
	m.stored = cfg
	if err := m.publish(); err != nil {
		return nil, err
	}
	if d.found {
		m.file = stateOf(m.path, d.data)
		if err := m.saveSecret(); err != nil {
			return nil, err
		}
	} else {
		if err := m.save(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// ConfigPath returns the absolute path of tamamo.yaml.
func (m *Manager) ConfigPath() string { return m.path }

// OnSiteRename registers fn to be told when sites get new IDs because they
// were renamed (old ID -> new ID).
func (m *Manager) OnSiteRename(fn func(map[string]string)) {
	m.mu.Lock()
	m.renameSubs = append(m.renameSubs, fn)
	m.mu.Unlock()
}

func (m *Manager) notifyRenames(r map[string]string) {
	if len(r) == 0 {
		return
	}
	m.mu.Lock()
	subs := append([]func(map[string]string){}, m.renameSubs...)
	m.mu.Unlock()
	for _, fn := range subs {
		fn(r)
	}
}

func hostKey(st *Site) string {
	h := append([]string{}, st.Hosts...)
	sort.Strings(h)
	return strings.Join(h, ",")
}

// siteRenames finds sites whose ID changed: a new ID whose hosts are the
// same as those of an ID that went away.
func siteRenames(prev, next *Config) map[string]string {
	if prev == nil || next == nil {
		return nil
	}
	nextIDs := map[string]bool{}
	for _, st := range next.Sites {
		nextIDs[st.ID] = true
	}
	gone := map[string]string{} // host key -> old ID
	prevIDs := map[string]bool{}
	for i := range prev.Sites {
		st := &prev.Sites[i]
		prevIDs[st.ID] = true
		if !nextIDs[st.ID] {
			gone[hostKey(st)] = st.ID
		}
	}
	out := map[string]string{}
	for i := range next.Sites {
		st := &next.Sites[i]
		if prevIDs[st.ID] {
			continue
		}
		if old, ok := gone[hostKey(st)]; ok {
			out[old] = st.ID
		}
	}
	return out
}

func (m *Manager) saveSecret() error {
	if m.stored.Secret == m.secretOnDisk {
		return nil
	}
	if err := writeAtomic(m.secretPath, []byte(m.stored.Secret+"\n"), 0o600); err != nil {
		return err
	}
	m.secretOnDisk = m.stored.Secret
	return nil
}

// save writes tamamo.yaml (and secret.key when the key changed). Callers
// hold m.mu (or own m exclusively).
func (m *Manager) save() error {
	b, err := MarshalConfigYAML(m.stored)
	if err != nil {
		return err
	}
	if err := writeAtomic(m.path, b, 0o640); err != nil {
		return err
	}
	m.file = stateOf(m.path, b)
	return m.saveSecret()
}

// diskChange compares a file with what we last saw. It updates st when only
// the timestamp moved (same content).
func diskChange(path string, st *fileState) (changed, gone bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, errors.Is(err, os.ErrNotExist) && st.exists
	}
	if st.exists && fi.Size() == st.size && fi.ModTime().Equal(st.mtime) {
		return false, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	if sum := sha256.Sum256(b); st.exists && sum == st.sum {
		st.size, st.mtime = fi.Size(), fi.ModTime()
		return false, false
	}
	return true, false
}

// Watch reloads the settings whenever tamamo.yaml is changed on disk by
// someone else, until ctx is done.
func (m *Manager) Watch(ctx context.Context) { m.watch(ctx, WatchInterval) }

func (m *Manager) watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = m.checkDisk()
		}
	}
}

// checkDisk looks at the file once and reloads it if it changed.
func (m *Manager) checkDisk() (reloaded bool, err error) {
	m.mu.Lock()
	changed, gone := diskChange(m.path, &m.file)
	if gone {
		slog.Warn("the settings file was removed; writing it again from the running settings", "file", m.path)
		m.file = fileState{}
		err = m.save()
		m.mu.Unlock()
		if err != nil {
			slog.Error("could not write the settings file", "err", err)
		}
		return false, err
	}
	if !changed {
		m.mu.Unlock()
		return false, nil
	}
	prev := m.stored
	err = m.reloadLocked()
	if err != nil {
		// Remember the broken content so the error is logged once, not
		// every few seconds; the next edit is noticed again.
		m.file = statNow(m.path)
		m.mu.Unlock()
		slog.Error("could not reload the settings; keeping the running ones", "err", err)
		return false, err
	}
	next := m.stored
	subs := append([]func(*Config){}, m.subs...)
	m.mu.Unlock()
	slog.Info("settings reloaded from disk", "file", m.path)
	m.notifyRenames(siteRenames(prev, next))
	for _, s := range subs {
		s(m.Get())
	}
	return true, nil
}

func (m *Manager) reloadLocked() error {
	d, err := m.readDisk()
	if err != nil {
		return err
	}
	if !d.found {
		return errors.New("the settings file is missing")
	}
	next := d.cfg
	next.Secret = m.stored.Secret
	if err := next.Validate(); err != nil {
		return fmt.Errorf("%s: %w", m.path, err)
	}
	prev := m.stored
	m.stored = next
	if err := m.publish(); err != nil {
		m.stored = prev
		return err
	}
	// The file is kept exactly as written (comments and all).
	m.file = stateOf(m.path, d.data)
	return nil
}
