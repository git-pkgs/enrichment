package from_enrichment

import (
	"context"
	"testing"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vulns"
)

// enrichment's tests define a fake with exactly Name, Query, QueryBatch, Get
// (target/vulnerabilities_test.go:18-32) and pass it where a vulns.Source is
// required (target/vulnerabilities.go:56). Adding a method to vulns.Source or
// changing any of these signatures breaks that fake.
type fakeSource struct{}

func (fakeSource) Name() string { return "fake" }

func (fakeSource) Query(context.Context, *purl.PURL) ([]vulns.Vulnerability, error) {
	return nil, nil
}

func (fakeSource) QueryBatch(context.Context, []*purl.PURL) ([][]vulns.Vulnerability, error) {
	return nil, nil
}

func (fakeSource) Get(context.Context, string) (*vulns.Vulnerability, error) {
	return nil, nil
}

func TestSourceInterfaceMethodSet(t *testing.T) {
	var src vulns.Source = fakeSource{}
	if got := src.Name(); got != "fake" {
		t.Fatalf("Name() = %q, want %q", got, "fake")
	}
}
