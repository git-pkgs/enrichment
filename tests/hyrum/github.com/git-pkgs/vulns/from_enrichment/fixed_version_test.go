package from_enrichment

import (
	"testing"

	"github.com/git-pkgs/vulns"
)

// enrichment calls v.FixedVersion(p.Type, p.FullName()) when the query PURL
// has no version (target/vulnerabilities.go:195). For pkg:npm/lodash that is
// ("npm", "lodash") against the fixture at target/vulnerabilities_test.go:49-56.
func TestFixedVersionForNpmLodash(t *testing.T) {
	v := vulns.Vulnerability{
		Affected: []vulns.Affected{
			{
				Package: vulns.Package{Ecosystem: "npm", Name: "lodash"},
				Ranges: []vulns.Range{
					{Type: "SEMVER", Events: []vulns.Event{{Introduced: "0"}, {Fixed: "4.17.21"}}},
				},
			},
		},
	}
	if got := v.FixedVersion("npm", "lodash"); got != "4.17.21" {
		t.Fatalf("FixedVersion(npm, lodash) = %q, want %q", got, "4.17.21")
	}
}
