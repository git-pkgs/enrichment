package hyrum

import (
	"testing"

	"github.com/git-pkgs/purl"
)

// vulnerabilities.go:111 allocates []*purl.PURL and stores MakePURL results.
// vulnerabilities_test.go:22-27 accepts *purl.PURL and []*purl.PURL as method
// parameters. This pins that both MakePURL and Parse yield values assignable
// to *purl.PURL.
func TestPURLPointerAssignment(t *testing.T) {
	purls := make([]*purl.PURL, 2)
	purls[0] = purl.MakePURL("npm", "lodash", "4.17.20")
	p, err := purl.Parse("pkg:pypi/requests@2.31.0")
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	purls[1] = p
	if purls[0] == nil || purls[1] == nil {
		t.Fatalf("purls contains nil: %v", purls)
	}
	if purls[0].Type != "npm" || purls[1].Type != "pypi" {
		t.Errorf("purls[0].Type=%q purls[1].Type=%q, want npm and pypi", purls[0].Type, purls[1].Type)
	}
}
