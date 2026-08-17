package from_enrichment

import (
	"testing"

	"github.com/git-pkgs/vulns"
)

// enrichment constructs vulns.Reference literals with Type and URL
// (target/vulnerabilities_test.go:46-47) and reads only ref.URL
// (target/vulnerabilities.go:283-284).
func TestReferenceFields(t *testing.T) {
	refs := []vulns.Reference{
		{Type: "ADVISORY", URL: "https://example.com/advisory"},
		{Type: "WEB", URL: ""},
	}
	if refs[0].URL != "https://example.com/advisory" {
		t.Errorf("URL = %q, want https://example.com/advisory", refs[0].URL)
	}
	if refs[1].URL != "" {
		t.Errorf("URL = %q, want empty", refs[1].URL)
	}
	if refs[0].Type != "ADVISORY" {
		t.Errorf("Type = %q, want ADVISORY", refs[0].Type)
	}
}
