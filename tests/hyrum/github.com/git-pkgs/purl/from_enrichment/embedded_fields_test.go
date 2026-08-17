package hyrum

import (
	"testing"

	"github.com/git-pkgs/purl"
)

// breaks.json: target commit 3fc2cd27461cebc50c14174bdee6ac0ea7129033 worked
// around purl v0.1.6-v0.1.10 switching the embedded PackageURL to a forked
// type, which broke callers that passed the struct across module boundaries.
// The target's remaining contract with purl is field-level: it reads .Type,
// .Namespace, .Name and .Version as strings on the *purl.PURL result of Parse
// and MakePURL and no longer depends on the embedded struct's package
// identity. This test pins those string fields so a future change to the
// embedding cannot silently alter the values the target reads.
func TestParseExposesEmbeddedStringFields(t *testing.T) {
	p, err := purl.Parse("pkg:npm/%40mycompany/utils@1.0.0?repository_url=https://npm.mycompany.com")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	var typ, ns, name, ver string = p.Type, p.Namespace, p.Name, p.Version
	if typ != "npm" {
		t.Errorf("p.Type = %q, want %q", typ, "npm")
	}
	if ns != "@mycompany" {
		t.Errorf("p.Namespace = %q, want %q", ns, "@mycompany")
	}
	if name != "utils" {
		t.Errorf("p.Name = %q, want %q", name, "utils")
	}
	if ver != "1.0.0" {
		t.Errorf("p.Version = %q, want %q", ver, "1.0.0")
	}
}
