package from_enrichment

import (
	"testing"

	"github.com/git-pkgs/vulns"
	"github.com/git-pkgs/vulns/osv"
)

// enrichment stores osv.New(osv.WithUserAgent(...)) into a vulns.Source field
// (target/vulnerabilities.go:76) and later calls Name() on it
// (target/vulnerabilities.go:102, 132).
func TestOSVNewWithUserAgentSatisfiesSource(t *testing.T) {
	var src vulns.Source = osv.New(osv.WithUserAgent("git-pkgs-enrichment/test"))
	if src == nil {
		t.Fatal("osv.New returned nil")
	}
	if got := src.Name(); got != "osv" {
		t.Fatalf("Name() = %q, want %q", got, "osv")
	}
}
