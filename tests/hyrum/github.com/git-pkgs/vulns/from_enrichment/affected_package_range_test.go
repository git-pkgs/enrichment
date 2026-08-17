package from_enrichment

import (
	"testing"

	"github.com/git-pkgs/vulns"
)

// enrichment ranges over v.Affected, reads affected.Package and
// affected.Ranges (target/vulnerabilities.go:198-206), reads pkg.PURL,
// pkg.Name, pkg.Ecosystem (target/vulnerabilities.go:235-244), and reads
// Range.Type, Range.Events, Event.Introduced, Event.Fixed, Event.LastAffected
// (target/vulnerabilities.go:212-227). Fixture values are from
// target/vulnerabilities_test.go:49-56, 102-120, 145-156.
func TestAffectedPackageRangeEventFields(t *testing.T) {
	affected := []vulns.Affected{
		{
			Package: vulns.Package{Ecosystem: "npm", Name: "lodash"},
			Ranges: []vulns.Range{
				{Type: "SEMVER", Events: []vulns.Event{{Introduced: "0"}, {Fixed: "4.17.21"}}},
			},
		},
		{
			Package: vulns.Package{Ecosystem: "npm", Name: "example"},
			Ranges: []vulns.Range{
				{Type: "SEMVER", Events: []vulns.Event{{Introduced: "0"}, {Fixed: "1.0.0"}}},
				{Type: "SEMVER", Events: []vulns.Event{{Introduced: "1.5.0"}, {Fixed: "2.0.0"}}},
			},
		},
		{
			Package: vulns.Package{Ecosystem: "Alpine", Name: "openssl"},
			Ranges: []vulns.Range{
				{Type: "ECOSYSTEM", Events: []vulns.Event{{Introduced: "0"}, {Fixed: "3.0.8-r1"}}},
			},
		},
	}

	if affected[0].Package.PURL != "" {
		t.Errorf("Package.PURL zero value = %q, want empty", affected[0].Package.PURL)
	}
	if affected[0].Package.Name != "lodash" {
		t.Errorf("Package.Name = %q, want lodash", affected[0].Package.Name)
	}
	if affected[0].Package.Ecosystem != "npm" {
		t.Errorf("Package.Ecosystem = %q, want npm", affected[0].Package.Ecosystem)
	}
	if affected[2].Package.Ecosystem != "Alpine" {
		t.Errorf("Package.Ecosystem = %q, want Alpine", affected[2].Package.Ecosystem)
	}
	if affected[2].Package.Name != "openssl" {
		t.Errorf("Package.Name = %q, want openssl", affected[2].Package.Name)
	}

	if affected[0].Ranges[0].Type != "SEMVER" {
		t.Errorf("Range.Type = %q, want SEMVER", affected[0].Ranges[0].Type)
	}
	if affected[2].Ranges[0].Type != "ECOSYSTEM" {
		t.Errorf("Range.Type = %q, want ECOSYSTEM", affected[2].Ranges[0].Type)
	}

	events := affected[1].Ranges[1].Events
	if len(events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(events))
	}
	if events[0].Introduced != "1.5.0" {
		t.Errorf("Event.Introduced = %q, want 1.5.0", events[0].Introduced)
	}
	if events[0].Fixed != "" {
		t.Errorf("Event.Fixed zero value = %q, want empty", events[0].Fixed)
	}
	if events[0].LastAffected != "" {
		t.Errorf("Event.LastAffected zero value = %q, want empty", events[0].LastAffected)
	}
	if events[1].Fixed != "2.0.0" {
		t.Errorf("Event.Fixed = %q, want 2.0.0", events[1].Fixed)
	}
	if events[1].Introduced != "" {
		t.Errorf("Event.Introduced zero value = %q, want empty", events[1].Introduced)
	}
}
