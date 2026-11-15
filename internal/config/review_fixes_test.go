package config

import "testing"

func TestRegexPatternsFollowCaseRules(t *testing.T) {
	rs := mustRules(t,
		Rule{Name: "path", Enabled: true, Action: ActionBlock, Match: Match{Paths: []string{"re:^/Admin$"}}},
		Rule{Name: "ua", Enabled: true, Action: ActionBlock, Match: Match{UserAgents: []string{"re:gptbot"}}},
	)
	if got := name(rs.Match(RuleRequest{Path: "/admin"})); got != "" {
		t.Errorf("re: path must stay case-sensitive, got %q", got)
	}
	if got := name(rs.Match(RuleRequest{Path: "/Admin"})); got != "path" {
		t.Errorf("re: path: got %q", got)
	}
	if got := name(rs.Match(RuleRequest{UserAgent: "Mozilla/5.0 GPTBot/1.0"})); got != "ua" {
		t.Errorf("re: user agent must ignore case, got %q", got)
	}
}

func TestCustomCSSMayMentionCredit(t *testing.T) {
	if err := CheckCustomCSS(".credit-card { color: red }"); err != nil {
		t.Errorf("unrelated class refused: %v", err)
	}
	if err := CheckCustomCSS(".tm-credit { display: none }"); err == nil {
		t.Error("credit line selector accepted")
	}
}

func TestModuleFollowsRenamedSite(t *testing.T) {
	c := Defaults()
	c.Sites = []Site{{Name: "Blog", Hosts: []string{"blog.example.com"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	oldID := c.Sites[0].ID
	c.Modules = []ModuleConfig{{Name: "limit", Enabled: true, Module: "plain", Sites: []string{oldID}}}
	c.Sites[0].Name = "Journal"
	if err := c.Validate(); err != nil {
		t.Fatalf("rename broke the module: %v", err)
	}
	if got := c.Modules[0].Sites[0]; got != c.Sites[0].ID || got == oldID {
		t.Errorf("module site = %q, want new ID %q", got, c.Sites[0].ID)
	}
}
