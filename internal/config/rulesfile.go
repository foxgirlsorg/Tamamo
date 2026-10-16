package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const rulesFileHeader = `Rules, checked top to bottom; the first match wins. This is the same
part of tamamo.yaml the web UI shows: "rules" are the global rules and
each site listed under "sites" has its own (sites not listed use the
global ones). Patterns: * is a wildcard, re: starts a regular expression.
action: allow | challenge | block.`

// ---- writing ----------------------------------------------------------------

func strNode(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

func intNode(v int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(v)}
}

func boolNode(v bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(v)}
}

func mapNode() *yaml.Node { return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"} }

func addPair(m *yaml.Node, key string, v *yaml.Node) *yaml.Node {
	k := strNode(key)
	m.Content = append(m.Content, k, v)
	return k
}

// shortList reports whether items fit on one line in flow style.
func shortList(items []string) bool {
	n := 0
	for _, s := range items {
		n += len(s) + 2
		if strings.ContainsAny(s, "\n#") {
			return false
		}
	}
	return len(items) <= 8 && n <= 70
}

func listNode(items []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	if shortList(items) {
		n.Style = yaml.FlowStyle
	}
	for _, s := range items {
		n.Content = append(n.Content, strNode(s))
	}
	return n
}

func nonEmpty(list []string) []string {
	var out []string
	for _, s := range list {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func ruleNode(r *Rule) *yaml.Node {
	m := mapNode()
	addPair(m, "name", strNode(r.Name))
	addPair(m, "action", strNode(r.Action))
	if r.Difficulty > 0 {
		addPair(m, "difficulty", intNode(r.Difficulty))
	}
	if !r.Enabled {
		addPair(m, "enabled", boolNode(false))
	}
	for _, f := range []struct {
		key  string
		list []string
	}{
		{"paths", r.Match.Paths}, {"user_agents", r.Match.UserAgents}, {"ips", r.Match.IPs},
		{"methods", r.Match.Methods}, {"hosts", r.Match.Hosts},
	} {
		if l := nonEmpty(f.list); len(l) > 0 {
			addPair(m, f.key, listNode(l))
		}
	}
	var hs []HeaderMatch
	dup := false
	seen := map[string]bool{}
	for _, h := range r.Match.Headers {
		if strings.TrimSpace(h.Name) == "" {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(h.Name))
		dup = dup || seen[k]
		seen[k] = true
		hs = append(hs, h)
	}
	if len(hs) > 0 {
		if dup {
			// The same header twice can't be a map key twice: use a list.
			seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for _, h := range hs {
				hm := mapNode()
				hm.Style = yaml.FlowStyle
				addPair(hm, "name", strNode(h.Name))
				addPair(hm, "pattern", strNode(h.Pattern))
				seq.Content = append(seq.Content, hm)
			}
			addPair(m, "headers", seq)
		} else {
			hm := mapNode()
			for _, h := range hs {
				addPair(hm, h.Name, strNode(h.Pattern))
			}
			addPair(m, "headers", hm)
		}
	}
	if r.Note != "" {
		addPair(m, "note", strNode(r.Note))
	}
	return m
}

func rulesNode(rules []Rule) *yaml.Node {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for i := range rules {
		seq.Content = append(seq.Content, ruleNode(&rules[i]))
	}
	if len(seq.Content) == 0 {
		seq.Style = yaml.FlowStyle
	}
	return seq
}

// MarshalRulesYAML renders the rules part of the settings: the global
// rules and the rules of every site that has its own, sites by name.
func MarshalRulesYAML(cfg *Config) ([]byte, error) {
	root := mapNode()
	addPair(root, "rules", rulesNode(cfg.Rules))
	sites := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for i := range cfg.Sites {
		st := &cfg.Sites[i]
		if !st.OwnRules {
			continue
		}
		sm := mapNode()
		addPair(sm, "name", strNode(st.Name))
		addPair(sm, "rules", rulesNode(st.Rules))
		sites.Content = append(sites.Content, sm)
	}
	if len(sites.Content) == 0 {
		sites.Style = yaml.FlowStyle
	}
	addPair(root, "sites", sites)
	doc := &yaml.Node{Kind: yaml.DocumentNode, HeadComment: rulesFileHeader, Content: []*yaml.Node{root}}
	return encodeDoc(doc)
}

// ---- reading ----------------------------------------------------------------

func errAt(n *yaml.Node, format string, args ...any) error {
	return fmt.Errorf("line %d: %s", n.Line, fmt.Sprintf(format, args...))
}

// yamlError turns yaml.v3's "yaml: line 3: ..." into "line 3: ...".
func yamlError(err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) && len(te.Errors) > 0 {
		return errors.New(strings.TrimSpace(te.Errors[0]))
	}
	return errors.New(strings.TrimPrefix(err.Error(), "yaml: "))
}

func deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	return n
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

func scalar(n *yaml.Node, key string) (string, error) {
	if n.Kind != yaml.ScalarNode {
		return "", errAt(n, "%s must be a single value", key)
	}
	if isNull(n) {
		return "", nil
	}
	return n.Value, nil
}

func strList(n *yaml.Node, key string) ([]string, error) {
	switch {
	case isNull(n):
		return nil, nil
	case n.Kind == yaml.ScalarNode:
		return []string{n.Value}, nil
	case n.Kind == yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			c = deref(c)
			if c.Kind != yaml.ScalarNode {
				return nil, errAt(c, "every entry of %s must be a single value", key)
			}
			if !isNull(c) {
				out = append(out, c.Value)
			}
		}
		return out, nil
	}
	return nil, errAt(n, "%s must be a list, like [/a, /b]", key)
}

func boolValue(n *yaml.Node, key string) (bool, error) {
	v, err := scalar(n, key)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(v) {
	case "true", "yes", "on":
		return true, nil
	case "false", "no", "off":
		return false, nil
	}
	return false, errAt(n, "%s must be true or false", key)
}

func intValue(n *yaml.Node, key string) (int, error) {
	v, err := scalar(n, key)
	if err != nil {
		return 0, err
	}
	if v == "" {
		return 0, nil
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return 0, errAt(n, "%s must be a whole number", key)
	}
	return i, nil
}

func parseAction(n *yaml.Node) (string, error) {
	v, err := scalar(n, "action")
	if err != nil {
		return "", err
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "allow":
		return ActionAllow, nil
	case "challenge":
		return ActionChallenge, nil
	case "block", "deny":
		return ActionBlock, nil
	case "weigh":
		return "", errAt(n, "WEIGH isn't supported, use allow/challenge/block")
	}
	return "", errAt(n, "action %q must be allow, challenge or block", v)
}

func headerMap(n *yaml.Node, regex bool) ([]HeaderMatch, error) {
	var out []HeaderMatch
	add := func(name, pattern string) {
		if regex {
			pattern = "re:" + pattern
		}
		out = append(out, HeaderMatch{Name: name, Pattern: pattern})
	}
	switch {
	case isNull(n):
		return nil, nil
	case n.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := deref(n.Content[i]), deref(n.Content[i+1])
			name, err := scalar(k, "a header name")
			if err != nil {
				return nil, err
			}
			p, err := scalar(v, "header "+name)
			if err != nil {
				return nil, err
			}
			add(name, p)
		}
		return out, nil
	case n.Kind == yaml.SequenceNode:
		// [{name: X, pattern: Y}, ...]
		for _, c := range n.Content {
			c = deref(c)
			if c.Kind != yaml.MappingNode {
				return nil, errAt(c, "every header must look like {name: Accept, pattern: \"*html*\"}")
			}
			var name, pattern string
			for i := 0; i+1 < len(c.Content); i += 2 {
				k, v := deref(c.Content[i]), deref(c.Content[i+1])
				s, err := scalar(v, k.Value)
				if err != nil {
					return nil, err
				}
				switch k.Value {
				case "name":
					name = s
				case "pattern":
					pattern = s
				default:
					return nil, errAt(k, "unknown key %q in a header (use name and pattern)", k.Value)
				}
			}
			add(name, pattern)
		}
		return out, nil
	}
	return nil, errAt(n, "headers must map a header name to a pattern, like {Accept-Language: \"*de*\"}")
}

// parseRule reads one rule. It also accepts the alternative keys path_regex,
// user_agent_regex, remote_addresses and challenge, and upper-case actions.
func parseRule(n *yaml.Node) (Rule, error) {
	r := Rule{Enabled: true}
	if n.Kind != yaml.MappingNode {
		return r, errAt(n, "each rule must be a set of keys like id, name, action and paths")
	}
	hasAction := false
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := deref(n.Content[i]), deref(n.Content[i+1])
		var err error
		var list []string
		switch k.Value {
		case "id":
			r.ID, err = scalar(v, "id")
		case "name":
			r.Name, err = scalar(v, "name")
		case "note":
			r.Note, err = scalar(v, "note")
		case "enabled":
			r.Enabled, err = boolValue(v, "enabled")
		case "action":
			r.Action, err = parseAction(v)
			hasAction = true
		case "difficulty":
			r.Difficulty, err = intValue(v, "difficulty")
		case "challenge": // challenge: {difficulty: 4, algorithm: fast}
			if v.Kind != yaml.MappingNode {
				return r, errAt(v, "challenge must contain difficulty, like {difficulty: 4}")
			}
			for j := 0; j+1 < len(v.Content); j += 2 {
				if ck := deref(v.Content[j]); ck.Value == "difficulty" {
					if r.Difficulty, err = intValue(deref(v.Content[j+1]), "difficulty"); err != nil {
						return r, err
					}
				}
			}
		case "paths":
			list, err = strList(v, k.Value)
			r.Match.Paths = append(r.Match.Paths, list...)
		case "path_regex":
			list, err = strList(v, k.Value)
			for _, s := range list {
				r.Match.Paths = append(r.Match.Paths, "re:"+s)
			}
		case "user_agents":
			list, err = strList(v, k.Value)
			r.Match.UserAgents = append(r.Match.UserAgents, list...)
		case "user_agent_regex":
			list, err = strList(v, k.Value)
			for _, s := range list {
				r.Match.UserAgents = append(r.Match.UserAgents, "re:"+s)
			}
		case "ips", "remote_addresses":
			list, err = strList(v, k.Value)
			r.Match.IPs = append(r.Match.IPs, list...)
		case "methods":
			list, err = strList(v, k.Value)
			r.Match.Methods = append(r.Match.Methods, list...)
		case "hosts":
			list, err = strList(v, k.Value)
			r.Match.Hosts = append(r.Match.Hosts, list...)
		case "headers", "headers_regex":
			var hs []HeaderMatch
			hs, err = headerMap(v, k.Value == "headers_regex")
			r.Match.Headers = append(r.Match.Headers, hs...)
		case "import":
			return r, errAt(k, "import isn't supported; copy the rules into this file")
		case "expression":
			return r, errAt(k, "expression isn't supported; use paths, user_agents, ips, methods, hosts or headers")
		default:
			return r, errAt(k, "unknown key %q in a rule", k.Value)
		}
		if err != nil {
			return r, err
		}
	}
	if !hasAction {
		return r, errAt(n, "rule %q needs an action: allow, challenge or block", r.Name)
	}
	if r.Name == "" {
		r.Name = r.ID
	}
	if _, err := CompileRules([]Rule{r}); err != nil {
		return r, errAt(n, "%v", err)
	}
	return r, nil
}

// parseRules reads a list of rules. IDs are not read from the file: they
// are derived from the names when the config is validated.
func parseRules(n *yaml.Node, where string) ([]Rule, error) {
	out := []Rule{}
	if isNull(n) {
		return out, nil
	}
	if n.Kind != yaml.SequenceNode {
		return nil, errAt(n, "%s must be a list of rules (each starting with \"- \")", where)
	}
	for _, c := range n.Content {
		r, err := parseRule(deref(c))
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// Top-level keys of other policy file formats that have no meaning here.
var ignoredPolicyKeys = map[string]bool{
	"dnsbl": true, "openGraph": true, "opengraph": true, "status_codes": true, "store": true,
	"thresholds": true, "impressum": true, "logging": true,
}

// ApplyRulesYAML parses a rules document into cfg: the global rules ("rules",
// or "global"/"bots" as older files and other tools call them), and for
// every site it lists, its own rules. Sites it doesn't list follow the
// global rules. Errors name the line they were found on.
func ApplyRulesYAML(cfg *Config, data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return yamlError(err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return errors.New("the rules are empty; write at least \"rules: []\"")
	}
	root := deref(doc.Content[0])
	if root.Kind != yaml.MappingNode {
		return errAt(root, "the rules must start with \"rules:\"")
	}
	var global []Rule
	haveGlobal := false
	siteRules := map[string][]Rule{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := deref(root.Content[i]), deref(root.Content[i+1])
		switch k.Value {
		case "rules", "global", "bots":
			if haveGlobal {
				return errAt(k, "the global rules are listed twice")
			}
			rs, err := parseRules(v, "rules")
			if err != nil {
				return err
			}
			global, haveGlobal = rs, true
		case "sites":
			if err := parseSites(cfg, v, siteRules); err != nil {
				return err
			}
		default:
			if ignoredPolicyKeys[k.Value] {
				continue
			}
			return errAt(k, "unknown key %q (expected rules or sites)", k.Value)
		}
	}
	if !haveGlobal {
		return errAt(root, "the global rules are missing (write \"rules: []\" for none)")
	}
	cfg.Rules = global
	for i := range cfg.Sites {
		st := &cfg.Sites[i]
		if rs, ok := siteRules[st.ID]; ok {
			st.OwnRules = true
			st.Rules = rs
		} else {
			st.OwnRules = false
		}
	}
	return nil
}

func parseSites(cfg *Config, n *yaml.Node, into map[string][]Rule) error {
	if isNull(n) {
		return nil
	}
	if n.Kind != yaml.SequenceNode {
		return errAt(n, "sites must be a list, each entry starting with \"- name: <site name>\"")
	}
	// A site can be named by its name, its ID or one of its hosts.
	find := func(s string) (string, bool) {
		l := strings.ToLower(s)
		for _, st := range cfg.Sites {
			if strings.ToLower(st.Name) == l || st.ID == s {
				return st.ID, true
			}
		}
		for _, st := range cfg.Sites {
			for _, h := range st.Hosts {
				if strings.ToLower(h) == l {
					return st.ID, true
				}
			}
		}
		return "", false
	}
	for _, c := range n.Content {
		c = deref(c)
		if c.Kind != yaml.MappingNode {
			return errAt(c, "each site must look like \"- name: <site name>\" followed by \"rules:\"")
		}
		var name string
		var nameNode, rulesNode *yaml.Node
		for i := 0; i+1 < len(c.Content); i += 2 {
			k, v := deref(c.Content[i]), deref(c.Content[i+1])
			switch k.Value {
			case "name", "site", "id":
				s, err := scalar(v, k.Value)
				if err != nil {
					return err
				}
				name, nameNode = strings.TrimSpace(s), v
			case "rules":
				rulesNode = v
			default:
				return errAt(k, "unknown key %q in a site (expected name and rules)", k.Value)
			}
		}
		if nameNode == nil || name == "" {
			return errAt(c, "the site entry needs \"name: <site name>\"")
		}
		id, ok := find(name)
		if !ok {
			var names []string
			for _, st := range cfg.Sites {
				names = append(names, st.Name)
			}
			if len(names) == 0 {
				return errAt(nameNode, "there is no site called %q (no sites are set up yet)", name)
			}
			return errAt(nameNode, "there is no site called %q (sites: %s)", name, strings.Join(names, ", "))
		}
		if _, dup := into[id]; dup {
			return errAt(nameNode, "site %q is listed twice", name)
		}
		rs := []Rule{}
		if rulesNode != nil {
			var err error
			if rs, err = parseRules(rulesNode, "the rules of "+name); err != nil {
				return err
			}
		}
		into[id] = rs
	}
	return nil
}
