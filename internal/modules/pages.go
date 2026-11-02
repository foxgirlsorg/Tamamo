package modules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Files of a page module folder with a special meaning. Every other file is
// served as-is under the module's URL.
const (
	HeadFile   = "head.html" // inserted at the end of <head>
	BodyFile   = "body.html" // inserted at the end of <body>, before the credit line
	StyleFile  = "style.css" // linked from <head>
	ScriptFile = "script.js" // loaded with defer
	maxSnippet = 256 << 10   // head.html / body.html size limit
	maxListing = 500         // files listed per module
)

// PlaceholderURL in head.html and body.html is replaced with the module's
// base URL (e.g. "/.tamamo/modules/banner"), so snippets can reference their
// own files: <img src="{module}/logo.svg">.
const PlaceholderURL = "{module}"

var pageName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidPageName reports whether name can be a page module's folder name.
func ValidPageName(name string) bool { return pageName.MatchString(name) }

// PageFiles is the content of one page module folder.
type PageFiles struct {
	Name    string
	Head    string // head.html, with unclosed elements closed
	Body    string // body.html, likewise
	Style   bool   // style.css exists
	Script  bool   // script.js exists
	Version string // changes whenever one of the four files changes
}

// Snippets returns Head and Body with PlaceholderURL replaced by base + "/" + Name.
func (p PageFiles) Snippets(base string) (head, body string) {
	u := strings.TrimRight(base, "/") + "/" + p.Name
	return strings.ReplaceAll(p.Head, PlaceholderURL, u), strings.ReplaceAll(p.Body, PlaceholderURL, u)
}

type pageCacheEntry struct {
	sig   string
	files PageFiles
}

var (
	pageCacheMu sync.Mutex
	pageCache   = map[string]pageCacheEntry{}
)

// LoadPage reads the page module name from dir (normally <data>/modules).
// Results are cached until one of the files changes. A missing folder is an
// error wrapping fs.ErrNotExist.
func LoadPage(dir, name string) (PageFiles, error) {
	if !ValidPageName(name) {
		return PageFiles{}, fmt.Errorf("%q is not a valid page module name", name)
	}
	if dir == "" {
		return PageFiles{}, fmt.Errorf("page module %s: no data directory: %w", name, fs.ErrNotExist)
	}
	root, err := os.OpenRoot(filepath.Join(dir, name))
	if err != nil {
		return PageFiles{}, err
	}
	defer root.Close()

	var sig strings.Builder
	infos := map[string]fs.FileInfo{}
	for _, f := range []string{HeadFile, BodyFile, StyleFile, ScriptFile} {
		fi, err := root.Stat(f)
		if err != nil || !fi.Mode().IsRegular() {
			sig.WriteString("-|")
			continue
		}
		infos[f] = fi
		fmt.Fprintf(&sig, "%d.%d|", fi.Size(), fi.ModTime().UnixNano())
	}
	key := filepath.Join(dir, name)
	pageCacheMu.Lock()
	ce, ok := pageCache[key]
	pageCacheMu.Unlock()
	if ok && ce.sig == sig.String() {
		return ce.files, nil
	}

	pf := PageFiles{Name: name, Style: infos[StyleFile] != nil, Script: infos[ScriptFile] != nil}
	read := func(f string) (string, error) {
		if infos[f] == nil {
			return "", nil
		}
		if infos[f].Size() > maxSnippet {
			return "", fmt.Errorf("page module %s: %s is larger than %d KB", name, f, maxSnippet>>10)
		}
		fh, err := root.Open(f)
		if err != nil {
			return "", err
		}
		defer fh.Close()
		b, err := io.ReadAll(io.LimitReader(fh, maxSnippet+1))
		if err != nil {
			return "", err
		}
		return CloseFragment(string(b)), nil
	}
	if pf.Head, err = read(HeadFile); err != nil {
		return PageFiles{}, err
	}
	if pf.Body, err = read(BodyFile); err != nil {
		return PageFiles{}, err
	}
	sum := sha256.Sum256([]byte(sig.String()))
	pf.Version = hex.EncodeToString(sum[:6])

	pageCacheMu.Lock()
	if len(pageCache) > 1000 {
		clear(pageCache)
	}
	pageCache[key] = pageCacheEntry{sig: sig.String(), files: pf}
	pageCacheMu.Unlock()
	return pf, nil
}

// PageListing is one page module folder found on disk.
type PageListing struct {
	Name  string   `json:"name"`
	Files []string `json:"files"`
}

// ListPages lists the page module folders in dir and their files (dotfiles
// skipped). A missing dir is not an error.
func ListPages(dir string) ([]PageListing, error) {
	out := []PageListing{}
	if dir == "" {
		return out, nil
	}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	for _, e := range ents {
		if !e.IsDir() || !ValidPageName(e.Name()) {
			continue
		}
		pl := PageListing{Name: e.Name(), Files: []string{}}
		base := filepath.Join(dir, e.Name())
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if p != base && strings.HasPrefix(d.Name(), ".") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(base, p)
			if err != nil {
				return nil
			}
			pl.Files = append(pl.Files, filepath.ToSlash(rel))
			if len(pl.Files) >= maxListing {
				return fs.SkipAll
			}
			return nil
		})
		sort.Strings(pl.Files)
		out = append(out, pl)
	}
	return out, nil
}

var fileTypes = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".html":  "text/html; charset=utf-8",
	".htm":   "text/html; charset=utf-8",
	".json":  "application/json",
	".map":   "application/json",
	".wasm":  "application/wasm",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".webp":  "image/webp",
	".avif":  "image/avif",
	".ico":   "image/x-icon",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".ttf":   "font/ttf",
	".otf":   "font/otf",
	".txt":   "text/plain; charset=utf-8",
	".mp4":   "video/mp4",
	".webm":  "video/webm",
	".mp3":   "audio/mpeg",
	".ogg":   "audio/ogg",
}

// ContentType returns the MIME type served for a file name.
func ContentType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if ct := fileTypes[ext]; ct != "" {
		return ct
	}
	if ct := mime.TypeByExtension(ext); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

// ServeFile serves file (a slash-separated path) of the page module name in
// dir. head.html and body.html, dotfiles, traversal attempts, symlinks
// leaving the folder and anything that isn't a regular file answer 404.
func ServeFile(w http.ResponseWriter, r *http.Request, dir, name, file string) {
	if dir == "" || !ValidPageName(name) || !safeFile(file) || file == HeadFile || file == BodyFile {
		http.NotFound(w, r)
		return
	}
	root, err := os.OpenRoot(filepath.Join(dir, name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer root.Close()
	f, err := root.Open(filepath.FromSlash(file))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ContentType(file))
	h.Set("X-Content-Type-Options", "nosniff")
	switch strings.ToLower(path.Ext(file)) {
	case ".svg", ".html", ".htm", ".xml":
		// Opened directly, these are documents on the protected origin.
		h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:")
	}
	if r.URL.Query().Get("v") != "" {
		h.Set("Cache-Control", "public, max-age=86400")
	} else {
		h.Set("Cache-Control", "public, max-age=300")
	}
	http.ServeContent(w, r, path.Base(file), fi.ModTime(), f)
}

func safeFile(file string) bool {
	if file == "" || len(file) > 512 || !fs.ValidPath(file) || strings.ContainsAny(file, "\\:\x00") {
		return false
	}
	for _, seg := range strings.Split(file, "/") {
		if seg == "" || strings.HasPrefix(seg, ".") {
			return false
		}
	}
	return true
}

// ---- HTML fragment closing --------------------------------------------------

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

var (
	voidElements = set("area base br col embed hr img input link meta param source track wbr keygen")
	rawElements  = set("script style textarea title xmp iframe noembed noframes")
	// Document-level tags are dropped: a snippet must not open or end the
	// document, head or body.
	structural = set("html head body frameset")
)

// CloseFragment makes an HTML snippet safe to embed in the middle of a page:
// it closes every element, comment and raw-text element (script, style…) the
// snippet leaves open, drops <html>, <head> and <body> tags and cuts the
// snippet at <plaintext>. Whatever the snippet contains, markup after it
// stays where it is in the document tree. Extra closing tags are harmless in
// HTML, so when in doubt it closes.
func CloseFragment(s string) string {
	var out strings.Builder
	var stack []string
	foreign := func() bool {
		for _, n := range stack {
			if n == "svg" || n == "math" {
				return true
			}
		}
		return false
	}
	i := 0
loop:
	for i < len(s) {
		j := strings.IndexByte(s[i:], '<')
		if j < 0 {
			out.WriteString(s[i:])
			break
		}
		out.WriteString(s[i : i+j])
		i += j
		rest := s[i:]
		switch {
		case strings.HasPrefix(rest, "<!--"):
			end := strings.Index(rest[4:], "-->")
			if end < 0 {
				out.WriteString(rest)
				out.WriteString("-->")
				break loop
			}
			out.WriteString(rest[:4+end+3])
			i += 4 + end + 3
		case strings.HasPrefix(rest, "<!") || strings.HasPrefix(rest, "<?"):
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				break loop
			}
			out.WriteString(rest[:end+1])
			i += end + 1
		case strings.HasPrefix(rest, "</"):
			name := tagName(rest[2:])
			if name == "" {
				out.WriteString("&lt;")
				i++
				continue
			}
			end := tagEnd(rest)
			if end < 0 {
				break loop
			}
			i += end + 1
			if structural[name] {
				continue
			}
			idx := -1
			for k := len(stack) - 1; k >= 0; k-- {
				if stack[k] == name {
					idx = k
					break
				}
			}
			if idx < 0 {
				continue // stray end tag: drop it
			}
			for k := len(stack) - 1; k > idx; k-- {
				out.WriteString("</" + stack[k] + ">")
			}
			out.WriteString("</" + name + ">")
			stack = stack[:idx]
		default:
			name := tagName(rest[1:])
			if name == "" {
				out.WriteString("&lt;")
				i++
				continue
			}
			end := tagEnd(rest)
			if end < 0 || name == "plaintext" {
				break loop
			}
			tag := rest[:end+1]
			i += end + 1
			if structural[name] {
				continue
			}
			out.WriteString(tag)
			selfClosing := strings.HasSuffix(tag, "/>") && (foreign() || name == "svg" || name == "math")
			if voidElements[name] || selfClosing {
				continue
			}
			stack = append(stack, name)
			if rawElements[name] {
				closeAt := indexFold(s[i:], "</"+name)
				if closeAt < 0 {
					out.WriteString(s[i:])
					break loop
				}
				out.WriteString(s[i : i+closeAt])
				i += closeAt
			}
		}
	}
	for k := len(stack) - 1; k >= 0; k-- {
		out.WriteString("</" + stack[k] + ">")
	}
	return out.String()
}

// tagName reads the lower-cased tag name at the start of s ("" if s doesn't
// start with an ASCII letter).
func tagName(s string) string {
	if s == "" || !isLetter(s[0]) {
		return ""
	}
	n := 0
	for n < len(s) && (isLetter(s[n]) || (s[n] >= '0' && s[n] <= '9') || s[n] == '-' || s[n] == ':' || s[n] == '_' || s[n] == '.') {
		n++
	}
	return strings.ToLower(s[:n])
}

func isLetter(c byte) bool { return (c|0x20) >= 'a' && (c|0x20) <= 'z' }

// tagEnd returns the index of the '>' ending the tag starting at s[0],
// skipping quoted attribute values, or -1.
func tagEnd(s string) int {
	var q byte
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			if i > 0 && s[i-1] == '=' || (i > 1 && s[i-1] == ' ' && s[i-2] == '=') {
				q = c
			}
		case c == '>':
			return i
		}
	}
	return -1
}

// indexFold finds sub (ASCII) in s, ignoring ASCII case.
func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
}
