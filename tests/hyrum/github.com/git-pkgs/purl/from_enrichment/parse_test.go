package hyrum

import (
	"testing"

	"github.com/git-pkgs/purl"
)

// depsdev.go:54,123,152 parse a PURL string, then read p.Type, p.FullName()
// and p.Version to build a deps.dev request. enrichment_test.go drives this
// path with "pkg:npm/lodash@4.17.21".
func TestParseNPMWithVersion(t *testing.T) {
	p, err := purl.Parse("pkg:npm/lodash@4.17.21")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if p == nil {
		t.Fatal("Parse returned nil *PURL with nil error")
	}
	if p.Type != "npm" {
		t.Errorf("p.Type = %q, want %q", p.Type, "npm")
	}
	if p.FullName() != "lodash" {
		t.Errorf("p.FullName() = %q, want %q", p.FullName(), "lodash")
	}
	if p.Version != "4.17.21" {
		t.Errorf("p.Version = %q, want %q", p.Version, "4.17.21")
	}
}

// registries.go:77 parses a PURL and additionally guards p == nil before
// returning p.Type. enrichment_test.go:429 asserts purlType("pkg:npm/lodash")
// is "npm".
func TestParseReturnsNonNilOnSuccess(t *testing.T) {
	p, err := purl.Parse("pkg:npm/lodash")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if p == nil {
		t.Fatal("Parse returned nil *PURL with nil error")
	}
	if p.Type != "npm" {
		t.Errorf("p.Type = %q, want %q", p.Type, "npm")
	}
}

// registries.go:78 treats err != nil || p == nil as an empty type.
// enrichment_test.go:430 asserts purlType("not a purl") is "".
func TestParseInvalidReturnsError(t *testing.T) {
	p, err := purl.Parse("not a purl")
	if err == nil && p != nil {
		t.Fatalf("Parse(%q) = (%v, nil), want error or nil *PURL", "not a purl", p)
	}
}

// hybrid.go:114 and registries.go:133 read p.Qualifier("repository_url") and
// compare it to "" to route between backends. enrichment_test.go:407-411
// exercises both the absent and present cases.
func TestParseQualifierRepositoryURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"pkg:npm/lodash", ""},
		{"pkg:npm/lodash@4.17.21", ""},
		{"pkg:npm/%40mycompany/utils?repository_url=https://npm.mycompany.com", "https://npm.mycompany.com"},
		{"pkg:npm/%40mycompany/utils@1.0.0?repository_url=https://npm.mycompany.com", "https://npm.mycompany.com"},
		{"pkg:pypi/requests?repository_url=https://pypi.internal.com/simple", "https://pypi.internal.com/simple"},
	}
	for _, tt := range tests {
		p, err := purl.Parse(tt.in)
		if err != nil {
			t.Fatalf("Parse(%q) returned error: %v", tt.in, err)
		}
		if got := p.Qualifier("repository_url"); got != tt.want {
			t.Errorf("Parse(%q).Qualifier(%q) = %q, want %q", tt.in, "repository_url", got, tt.want)
		}
	}
}

// vulnerabilities.go:236 parses an OSV affected-package PURL and compares
// parsed.Type and parsed.FullName() against the query PURL built by MakePURL.
// TestVulnerabilityClientCheck requires the two agree for npm/lodash.
func TestParseAndMakePURLAgree(t *testing.T) {
	parsed, err := purl.Parse("pkg:npm/lodash@4.17.20")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	made := purl.MakePURL("npm", "lodash", "4.17.20")
	if made == nil {
		t.Fatal("MakePURL returned nil")
	}
	if parsed.Type != made.Type {
		t.Errorf("parsed.Type = %q, made.Type = %q; want equal", parsed.Type, made.Type)
	}
	if parsed.FullName() != made.FullName() {
		t.Errorf("parsed.FullName() = %q, made.FullName() = %q; want equal", parsed.FullName(), made.FullName())
	}
}
