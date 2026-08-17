package hyrum

import (
	"testing"

	"github.com/git-pkgs/purl"
)

// depsdev.go:59,128,157 feed p.Type from a parsed PURL into PURLTypeToDepsdev
// and treat "" as unsupported. enrichment_test.go:770 drives the supported
// path with "pkg:npm/lodash".
func TestPURLTypeToDepsdevNPM(t *testing.T) {
	p, err := purl.Parse("pkg:npm/lodash")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	system := purl.PURLTypeToDepsdev(p.Type)
	if system != "NPM" {
		t.Errorf("PURLTypeToDepsdev(%q) = %q, want %q", p.Type, system, "NPM")
	}
}

// depsdev.go:60 skips a PURL when PURLTypeToDepsdev returns "".
// enrichment_test.go:804 passes "pkg:unsupported/name" and expects it absent
// from the BulkLookup result map.
func TestPURLTypeToDepsdevUnsupported(t *testing.T) {
	p, err := purl.Parse("pkg:unsupported/name")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	system := purl.PURLTypeToDepsdev(p.Type)
	if system != "" {
		t.Errorf("PURLTypeToDepsdev(%q) = %q, want empty string", p.Type, system)
	}
}
