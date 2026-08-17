package from_enrichment

import (
	"testing"

	"github.com/git-pkgs/vulns"
)

// enrichment builds a Vulnerability with this exact Severity entry
// (target/vulnerabilities_test.go:43) and asserts SeverityLevel()=="high",
// CVSS().Score==7.5, CVSS().Version=="3.1"
// (target/vulnerabilities_test.go:74-82 via target/vulnerabilities.go:177,183-186).
func TestSeverityLevelAndCVSSFromCVSS31Vector(t *testing.T) {
	v := vulns.Vulnerability{
		Severity: []vulns.Severity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		},
	}

	if got := v.SeverityLevel(); got != "high" {
		t.Errorf("SeverityLevel() = %q, want %q", got, "high")
	}

	cvss := v.CVSS()
	if cvss == nil {
		t.Fatal("CVSS() = nil, want non-nil")
	}
	if cvss.Score != 7.5 {
		t.Errorf("CVSS().Score = %v, want 7.5", cvss.Score)
	}
	if cvss.Version != "3.1" {
		t.Errorf("CVSS().Version = %q, want %q", cvss.Version, "3.1")
	}
	if cvss.Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" {
		t.Errorf("CVSS().Vector = %q, want the input vector", cvss.Vector)
	}
}
