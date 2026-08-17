package hyrum

import (
	"testing"

	"github.com/git-pkgs/purl"
)

// vulnerabilities.go:144 calls EcosystemToPURLType on a trimmed ecosystem
// string. vulnerabilities_test.go drives this with "npm", "pypi", "alpine",
// "arch" and "github-actions".
func TestEcosystemToPURLType(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"npm", "npm"},
		{"pypi", "pypi"},
		{"alpine", "apk"},
		{"arch", "alpm"},
		{"github-actions", "githubactions"},
	}
	for _, tt := range tests {
		if got := purl.EcosystemToPURLType(tt.in); got != tt.want {
			t.Errorf("EcosystemToPURLType(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// vulnerabilities.go:155 short-circuits the ecosystem check when
// IsKnownType(EcosystemToPURLType(ecosystem)) is true.
// vulnerabilities_test.go passes "npm", "pypi", "alpine" and "arch" through
// this path and requires them to be accepted.
func TestIsKnownTypeForTargetEcosystems(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "alpine", "arch"} {
		pt := purl.EcosystemToPURLType(eco)
		if !purl.IsKnownType(pt) {
			t.Errorf("IsKnownType(EcosystemToPURLType(%q)=%q) = false, want true", eco, pt)
		}
	}
}

// vulnerabilities.go:158-159 range SupportedEcosystems() and compare each
// element via NormalizeEcosystem. vulnerabilities_test.go:206-212 relies on
// "github-actions" being reachable through this loop.
func TestSupportedEcosystemsContainsGitHubActions(t *testing.T) {
	found := false
	for _, supported := range purl.SupportedEcosystems() {
		if purl.NormalizeEcosystem(supported) == purl.NormalizeEcosystem("github-actions") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no element of SupportedEcosystems() normalizes equal to %q", "github-actions")
	}
}

// vulnerabilities.go:145 rejects an ecosystem when EcosystemToPURLType yields
// a value that is neither a known type nor found in SupportedEcosystems() via
// NormalizeEcosystem. vulnerabilities_test.go:278 asserts "unknown-ecosystem"
// is rejected.
func TestUnknownEcosystemRejected(t *testing.T) {
	pt := purl.EcosystemToPURLType("unknown-ecosystem")
	if purl.IsKnownType(pt) {
		t.Fatalf("IsKnownType(%q) = true, want false", pt)
	}
	for _, supported := range purl.SupportedEcosystems() {
		if purl.NormalizeEcosystem(supported) == purl.NormalizeEcosystem("unknown-ecosystem") {
			t.Fatalf("SupportedEcosystems() contains an entry normalizing to %q", "unknown-ecosystem")
		}
	}
}

// vulnerabilities.go:262 passes p.Type to PURLTypeToEcosystem and appends the
// result to the ecosystem candidate list. vulnerabilities_test.go:164 drives
// this with p.Type = "apk" and requires "alpine" to appear as a candidate so
// that vulns.Package.Ecosystem = "Alpine" matches via strings.EqualFold.
func TestPURLTypeToEcosystemAPK(t *testing.T) {
	if got := purl.PURLTypeToEcosystem("apk"); got != "alpine" {
		t.Errorf("PURLTypeToEcosystem(%q) = %q, want %q", "apk", got, "alpine")
	}
}

// vulnerabilities.go:263-264 pass p.Type and PURLTypeToEcosystem(p.Type) into
// EcosystemToOSV. vulnerabilities_test.go:62 drives this with p.Type = "npm"
// and requires "npm" among the candidates so vulns.Package.Ecosystem = "npm"
// matches.
func TestEcosystemToOSVNPM(t *testing.T) {
	if got := purl.EcosystemToOSV("npm"); got != "npm" {
		t.Errorf("EcosystemToOSV(%q) = %q, want %q", "npm", got, "npm")
	}
	if got := purl.EcosystemToOSV(purl.PURLTypeToEcosystem("npm")); got != "npm" {
		t.Errorf("EcosystemToOSV(PURLTypeToEcosystem(%q)) = %q, want %q", "npm", got, "npm")
	}
}
