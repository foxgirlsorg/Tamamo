// Package assets stores the images used on the challenge page: three mascot
// poses, an optional background and a favicon. Uploaded files live in
// dataDir/uploads and replace the embedded defaults.
package assets

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/tamamo/tamamo/web"
)

// Slots that can hold an image.
var Slots = []string{"checking", "success", "denied", "background", "favicon"}

// MaxUpload is the largest accepted image.
const MaxUpload = 4 << 20

var defaults = map[string]string{
	"checking": "mascot/checking.png",
	"success":  "mascot/success.png",
	"denied":   "mascot/denied.png",
	"favicon":  "mascot/checking.png",
}

var extFor = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
	"image/gif":  ".gif",
	"image/webp": ".webp",
}

type Store struct {
	dir string
	mu  sync.RWMutex
}

func New(dataDir string) (*Store, error) {
	dir := filepath.Join(dataDir, "uploads")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// DataDir returns the data directory the store was created in.
func (s *Store) DataDir() string { return filepath.Dir(s.dir) }

func ValidSlot(slot string) bool {
	for _, s := range Slots {
		if s == slot {
			return true
		}
	}
	return false
}

func (s *Store) customPath(slot string) (string, os.FileInfo) {
	// Fixed order, so a slot with several files always serves the same one.
	for _, ext := range []string{".png", ".jpg", ".gif", ".webp"} {
		p := filepath.Join(s.dir, slot+ext)
		if fi, err := os.Stat(p); err == nil {
			return p, fi
		}
	}
	return "", nil
}

// Open returns the image for a slot. ok is false when the slot has no image
// (for example "background" without an upload).
func (s *Store) Open(slot string) (data []byte, contentType string, mod time.Time, custom bool, ok bool) {
	if !ValidSlot(slot) {
		return nil, "", time.Time{}, false, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, fi := s.customPath(slot); p != "" {
		b, err := os.ReadFile(p)
		if err == nil {
			return b, http.DetectContentType(b), fi.ModTime(), true, true
		}
	}
	if d, has := defaults[slot]; has {
		b, err := fs.ReadFile(web.FS, d)
		if err == nil {
			return b, "image/png", time.Time{}, false, true
		}
	}
	return nil, "", time.Time{}, false, false
}

// Has reports whether a slot currently resolves to an image.
func (s *Store) Has(slot string) bool {
	_, _, _, _, ok := s.Open(slot)
	return ok
}

// Version is a short cache-busting token that changes when the image changes.
func (s *Store) Version(slot string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, fi := s.customPath(slot); fi != nil {
		return strconv.FormatInt(fi.ModTime().UnixNano(), 36)
	}
	return "d"
}

// Custom reports, per slot, whether an upload replaces the default.
func (s *Store) Custom() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]bool{}
	for _, slot := range Slots {
		p, _ := s.customPath(slot)
		out[slot] = p != ""
	}
	return out
}

// Save validates and stores an uploaded image (PNG, JPEG, GIF or WebP).
func (s *Store) Save(slot string, data []byte) error {
	if !ValidSlot(slot) {
		return fmt.Errorf("unknown image slot %q", slot)
	}
	if len(data) == 0 {
		return errors.New("the file is empty")
	}
	if len(data) > MaxUpload {
		return fmt.Errorf("images can be at most %d MB", MaxUpload>>20)
	}
	ct := http.DetectContentType(data)
	ext, ok := extFor[ct]
	if !ok {
		return errors.New("use a PNG, JPEG, GIF or WebP image")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range extFor {
		_ = os.Remove(filepath.Join(s.dir, slot+e))
	}
	tmp := filepath.Join(s.dir, slot+ext+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, slot+ext))
}

// Delete removes an upload, restoring the default image.
func (s *Store) Delete(slot string) error {
	if !ValidSlot(slot) {
		return fmt.Errorf("unknown image slot %q", slot)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range extFor {
		_ = os.Remove(filepath.Join(s.dir, slot+e))
	}
	return nil
}

// Serve writes the slot's image with caching headers. Requests carrying a
// version query (?v=...) are cached for a long time.
func (s *Store) Serve(w http.ResponseWriter, r *http.Request, slot string) {
	data, ct, mod, _, ok := s.Open(slot)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.URL.Query().Get("v") != "" {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=300")
	}
	http.ServeContent(w, r, slot, mod, bytes.NewReader(data))
}

// URLs returns slot -> URL under prefix for every slot that has an image.
func (s *Store) URLs(prefix string) map[string]string {
	out := map[string]string{}
	for _, slot := range Slots {
		if s.Has(slot) {
			out[slot] = prefix + "/" + slot + "?v=" + s.Version(slot)
		}
	}
	return out
}
