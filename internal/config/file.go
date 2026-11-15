package config

import (
	"bytes"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the settings file inside the data directory. It holds every
// setting, is meant to be read and edited by people, and is the same file
// the web UI edits.
const FileName = "tamamo.yaml"

// SecretFileName holds the key that signs challenges and visitor passes.
// It is not a setting anyone needs to read, so it lives on its own.
const SecretFileName = "secret.key"

func typeOf[T any]() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }

var unmarshalerType = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()

// ---- rules in YAML ----------------------------------------------------------

// UnmarshalYAML reads a rule in the short form used by the settings file.
func (r *Rule) UnmarshalYAML(n *yaml.Node) error {
	rr, err := parseRule(deref(n))
	if err != nil {
		return err
	}
	*r = rr
	return nil
}

// MarshalYAML writes a rule in the short form used by the settings file.
func (r Rule) MarshalYAML() (any, error) { return ruleNode(&r), nil }

// ---- checking keys ----------------------------------------------------------

func yamlFields(t reflect.Type) (map[string]reflect.Type, []string) {
	fields := map[string]reflect.Type{}
	var names []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		fields[tag] = f.Type
		names = append(names, tag)
	}
	return fields, names
}

func where(path string) string {
	if path == "" {
		return "the file"
	}
	return path
}

// unknownKey builds the "unknown setting" error, suggesting a close match.
func unknownKey(k *yaml.Node, path string, names []string) error {
	best, bestD := "", 3
	for _, n := range names {
		if d := editDistance(strings.ToLower(k.Value), n); d < bestD {
			best, bestD = n, d
		}
	}
	if best != "" {
		return errAt(k, "unknown setting %q in %s (did you mean %q?)", k.Value, where(path), best)
	}
	return errAt(k, "unknown setting %q in %s; it can contain: %s", k.Value, where(path), strings.Join(names, ", "))
}

func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

// checkKeys reports the first key in n that type t has no setting for, with
// its line number, so typos don't go unnoticed.
func checkKeys(n *yaml.Node, t reflect.Type, path string) error {
	n = deref(n)
	if n == nil || isNull(n) {
		return nil
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil // checks itself
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return errAt(n, "%s must be a group of settings (\"key: value\" lines)", where(path))
		}
		fields, names := yamlFields(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := deref(n.Content[i])
			ft, ok := fields[k.Value]
			if !ok {
				return unknownKey(k, path, names)
			}
			p := k.Value
			if path != "" {
				p = path + "." + k.Value
			}
			if err := checkKeys(n.Content[i+1], ft, p); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if n.Kind == yaml.SequenceNode {
			for _, c := range n.Content {
				if err := checkKeys(c, t.Elem(), path); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if err := checkKeys(n.Content[i+1], t.Elem(), path+"."+deref(n.Content[i]).Value); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func decodeInto(n *yaml.Node, out any, path string) error {
	if err := checkKeys(n, reflect.TypeOf(out), path); err != nil {
		return err
	}
	if err := n.Decode(out); err != nil {
		return yamlError(err)
	}
	return nil
}

// ---- reading ----------------------------------------------------------------

// ParseConfigYAML reads a settings file. Settings it leaves out keep their
// defaults, so an empty file is a working config. Errors name the line.
func ParseConfigYAML(data []byte) (*Config, error) {
	cfg := Defaults()
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, yamlError(err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return cfg, nil
	}
	root := deref(doc.Content[0])
	if isNull(root) {
		return cfg, nil
	}
	if root.Kind != yaml.MappingNode {
		return nil, errAt(root, "the settings file must be a list of \"section:\" groups, like \"server:\"")
	}
	fields, names := yamlFields(typeOf[Config]())
	names = append(names, "rules", "sites")
	cv := reflect.ValueOf(cfg).Elem()
	byTag := map[string]reflect.Value{}
	for i := 0; i < cv.NumField(); i++ {
		tag := strings.Split(cv.Type().Field(i).Tag.Get("yaml"), ",")[0]
		byTag[tag] = cv.Field(i)
	}
	var sitesNode *yaml.Node
	var scoped []scopedChange
	seen := map[string]bool{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := deref(root.Content[i]), deref(root.Content[i+1])
		if seen[k.Value] {
			return nil, errAt(k, "%q is listed twice", k.Value)
		}
		seen[k.Value] = true
		switch k.Value {
		case "sites":
			sitesNode = v
		case "rules":
			rs, err := parseRules(v, "rules")
			if err != nil {
				return nil, err
			}
			cfg.Rules = rs
		case "modules":
			pending, err := parseModules(cfg, v)
			if err != nil {
				return nil, err
			}
			scoped = pending
		default:
			if k.Value == "admin" && v.Kind == yaml.MappingNode {
				// admin.enabled was a setting before TAMAMO_ENABLE_API; ignore it.
				removeKey(v, "enabled")
			}
			if _, ok := fields[k.Value]; !ok || k.Value == "rules" || k.Value == "sites" {
				if k.Value == "secret" {
					return nil, errAt(k, "the signing secret isn't a setting; it is kept in %s", SecretFileName)
				}
				return nil, unknownKey(k, "", names)
			}
			if err := decodeInto(v, byTag[k.Value].Addr().Interface(), k.Value); err != nil {
				return nil, err
			}
		}
	}
	if cfg.Modules == nil {
		cfg.Modules = []ModuleConfig{}
	}
	if sitesNode != nil {
		sites, err := parseSiteList(cfg, sitesNode)
		if err != nil {
			return nil, err
		}
		cfg.Sites = sites
	}
	applyScoped(cfg, cfg.Sites, scoped)
	return cfg, nil
}

func clonePage(p Page) Page {
	out := p
	out.Translations = make(Translations, len(p.Translations))
	for k, v := range p.Translations {
		out.Translations[k] = v
	}
	return out
}

var siteKeys = []string{"name", "hosts", "target", "protection", "rules", "page"}

// parseSiteList reads the sites. A site's protection and page start from
// the global ones, so they only list what differs; rules replace the global
// rules for that site.
func parseSiteList(cfg *Config, n *yaml.Node) ([]Site, error) {
	out := []Site{}
	if isNull(n) {
		return out, nil
	}
	if n.Kind != yaml.SequenceNode {
		return nil, errAt(n, "sites must be a list, each site starting with \"- name: ...\"")
	}
	for _, c := range n.Content {
		c = deref(c)
		if c.Kind != yaml.MappingNode {
			return nil, errAt(c, "each site must be a group of settings starting with \"- name: ...\"")
		}
		var st Site
		for i := 0; i+1 < len(c.Content); i += 2 {
			k, v := deref(c.Content[i]), deref(c.Content[i+1])
			var err error
			switch k.Value {
			case "name":
				st.Name, err = scalar(v, "name")
			case "hosts":
				st.Hosts, err = strList(v, "hosts")
			case "target":
				st.Target, err = scalar(v, "target")
			case "protection":
				st.OwnProtection = true
				st.Protection = cfg.Protection
				err = decodeInto(v, &st.Protection, "protection")
			case "rules":
				st.OwnRules = true
				st.Rules, err = parseRules(v, "the rules of "+st.Name)
			case "page":
				st.OwnPage = true
				st.Page = clonePage(cfg.Page)
				err = decodeInto(v, &st.Page, "page")
			case "id", "site":
				err = errAt(k, "sites are known by their name; write \"name: ...\" instead of %q", k.Value)
			default:
				err = unknownKey(k, "a site", siteKeys)
			}
			if err != nil {
				return nil, err
			}
		}
		if st.Hosts == nil {
			st.Hosts = []string{}
		}
		if st.Rules == nil {
			st.Rules = []Rule{}
		}
		if !st.OwnPage {
			st.Page = cfg.Page
		}
		out = append(out, st)
	}
	return out, nil
}

// ---- writing ----------------------------------------------------------------

func encodeNode(v any) (*yaml.Node, error) {
	n := &yaml.Node{}
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return n, nil
}

func lookup(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func removeKey(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

func setKey(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = v
			return
		}
	}
	addPair(m, key, v)
}

func nodeEqual(a, b *yaml.Node) bool {
	if a.Kind != b.Kind || len(a.Content) != len(b.Content) {
		return false
	}
	if a.Kind == yaml.ScalarNode {
		return a.Value == b.Value
	}
	for i := range a.Content {
		if !nodeEqual(a.Content[i], b.Content[i]) {
			return false
		}
	}
	return true
}

// diffNode keeps the parts of a that differ from b (nil if none).
func diffNode(a, b *yaml.Node) *yaml.Node {
	if a.Kind != yaml.MappingNode || b == nil || b.Kind != yaml.MappingNode {
		if b != nil && nodeEqual(a, b) {
			return nil
		}
		return a
	}
	out := mapNode()
	for i := 0; i+1 < len(a.Content); i += 2 {
		k, av := a.Content[i], a.Content[i+1]
		if d := diffNode(av, lookup(b, k.Value)); d != nil {
			out.Content = append(out.Content, k, d)
		}
	}
	if len(out.Content) == 0 {
		return nil
	}
	return out
}

func emptyMap() *yaml.Node {
	m := mapNode()
	m.Style = yaml.FlowStyle
	return m
}

// translationsNode writes only what differs from base: changed words of
// languages base has, whole new languages, and "off" for removed ones.
func translationsNode(val, base Translations) (*yaml.Node, error) {
	m := mapNode()
	codes := make([]string, 0, len(val))
	for c := range val {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	for _, c := range codes {
		vn, err := encodeNode(val[c])
		if err != nil {
			return nil, err
		}
		if b, ok := base[c]; ok {
			bn, err := encodeNode(b)
			if err != nil {
				return nil, err
			}
			if vn = diffNode(vn, bn); vn == nil {
				continue
			}
		} else {
			// A new language: only the words it has.
			zero, err := encodeNode(PageTranslation{})
			if err != nil {
				return nil, err
			}
			if vn = diffNode(vn, zero); vn == nil {
				vn = emptyMap()
			}
		}
		addPair(m, c, vn)
	}
	var gone []string
	for c := range base {
		if _, ok := val[c]; !ok {
			gone = append(gone, c)
		}
	}
	sort.Strings(gone)
	for _, c := range gone {
		addPair(m, c, strNode("off"))
	}
	if len(m.Content) == 0 {
		return nil, nil
	}
	return m, nil
}

func pageNode(pg *Page) (*yaml.Node, error) {
	n, err := encodeNode(pg)
	if err != nil {
		return nil, err
	}
	tn, err := translationsNode(pg.Translations, DefaultTranslations())
	if err != nil {
		return nil, err
	}
	if tn == nil {
		tn = emptyMap()
	}
	setKey(n, "translations", tn)
	return n, nil
}

// sitePageNode writes only what a site's page changes from the global page.
func sitePageNode(pg, global *Page) (*yaml.Node, error) {
	a, err := encodeNode(pg)
	if err != nil {
		return nil, err
	}
	b, err := encodeNode(global)
	if err != nil {
		return nil, err
	}
	removeKey(a, "translations")
	removeKey(b, "translations")
	out := diffNode(a, b)
	if out == nil {
		out = mapNode()
	}
	tn, err := translationsNode(pg.Translations, global.Translations)
	if err != nil {
		return nil, err
	}
	if tn != nil {
		addPair(out, "translations", tn)
	}
	if len(out.Content) == 0 {
		return emptyMap(), nil
	}
	return out, nil
}

func siteNode(st *Site, c *Config) (*yaml.Node, error) {
	m := mapNode()
	addPair(m, "name", strNode(st.Name))
	addPair(m, "hosts", listNode(st.Hosts))
	if st.Target != "" {
		addPair(m, "target", strNode(st.Target))
	}
	if st.OwnProtection {
		a, err := encodeNode(st.Protection)
		if err != nil {
			return nil, err
		}
		b, err := encodeNode(c.Protection)
		if err != nil {
			return nil, err
		}
		d := diffNode(a, b)
		if d == nil {
			d = emptyMap()
		}
		addPair(m, "protection", d)
	}
	if st.OwnRules {
		addPair(m, "rules", rulesNode(st.Rules))
	}
	if st.OwnPage {
		pn, err := sitePageNode(&st.Page, &c.Page)
		if err != nil {
			return nil, err
		}
		addPair(m, "page", pn)
	}
	return m, nil
}

// MarshalConfigYAML renders the config as the commented settings file.
func MarshalConfigYAML(c *Config) ([]byte, error) {
	root := mapNode()
	for _, sec := range []struct {
		key string
		v   any
	}{{"server", c.Server}, {"protection", c.Protection}} {
		n, err := encodeNode(sec.v)
		if err != nil {
			return nil, err
		}
		addPair(root, sec.key, n)
	}
	addPair(root, "rules", rulesNode(c.Rules))
	pn, err := pageNode(&c.Page)
	if err != nil {
		return nil, err
	}
	addPair(root, "page", pn)

	sites := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for i := range c.Sites {
		sn, err := siteNode(&c.Sites[i], c)
		if err != nil {
			return nil, err
		}
		sites.Content = append(sites.Content, sn)
	}
	if len(sites.Content) == 0 {
		sites.Style = yaml.FlowStyle
	}
	addPair(root, "sites", sites)

	for _, sec := range []struct {
		key string
		v   any
	}{{"modules", modulesForFile(c)}, {"admin", c.Admin}, {"stats", c.Stats}} {
		n, err := encodeNode(sec.v)
		if err != nil {
			return nil, err
		}
		if n.Kind == yaml.SequenceNode && len(n.Content) == 0 {
			n.Style = yaml.FlowStyle
		}
		addPair(root, sec.key, n)
	}
	annotate(root, "")
	doc := &yaml.Node{Kind: yaml.DocumentNode, HeadComment: fileHeader, Content: []*yaml.Node{root}}
	return encodeDoc(doc)
}

func encodeDoc(doc *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	// A blank line before every top-level section keeps the file easy to scan.
	lines := strings.Split(buf.String(), "\n")
	var out []string
	for i, l := range lines {
		if i > 0 && l != "" && l[0] != ' ' && l[0] != '-' && !strings.HasPrefix(lines[i-1], "#") && lines[i-1] != "" {
			out = append(out, "")
		}
		if i > 0 && strings.HasPrefix(l, "#") && lines[i-1] != "" && !strings.HasPrefix(lines[i-1], "#") && !strings.HasPrefix(lines[i-1], " ") {
			out = append(out, "")
		}
		out = append(out, l)
	}
	return []byte(strings.Join(out, "\n")), nil
}

// annotate puts the explanations from fileComments above their keys.
func annotate(m *yaml.Node, path string) {
	if m.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		p := k.Value
		if path != "" {
			p = path + "." + k.Value
		}
		if c, ok := fileComments[p]; ok {
			k.HeadComment = c
		}
		if v.Kind == yaml.MappingNode && v.Style != yaml.FlowStyle && p != "page.translations" {
			annotate(v, p)
		}
	}
}

// modulesForFile lists modules with their sites by name rather than ID.
func modulesForFile(c *Config) []ModuleConfig {
	names := map[string]string{}
	for _, st := range c.Sites {
		names[st.ID] = st.Name
	}
	out := make([]ModuleConfig, len(c.Modules))
	for i, m := range c.Modules {
		m.Sites = append([]string{}, m.Sites...)
		for j, id := range m.Sites {
			if n, ok := names[id]; ok {
				m.Sites[j] = n
			}
		}
		out[i] = m
	}
	return out
}
