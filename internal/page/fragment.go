package page

import "strings"

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
