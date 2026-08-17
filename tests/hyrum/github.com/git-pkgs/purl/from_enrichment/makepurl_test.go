package hyrum

import (
	"testing"

	"github.com/git-pkgs/purl"
)

// vulnerabilities.go:151 calls MakePURL(ecosystem, name, version) and the
// result's .Type, .Namespace, .Name and .Version fields are read downstream.
// vulnerabilities_test.go:176-234 asserts those fields for alpine, arch and
// github-actions inputs.
func TestMakePURLMappedEcosystems(t *testing.T) {
	tests := []struct {
		ecosystem     string
		packageName   string
		version       string
		wantType      string
		wantNamespace string
		wantName      string
	}{
		{"alpine", "openssl", "3.0.0", "apk", "alpine", "openssl"},
		{"arch", "pacman", "6.0.2", "alpm", "arch", "pacman"},
		{"github-actions", "actions/checkout/action.yml", "v4", "githubactions", "actions", "checkout"},
	}
	for _, tt := range tests {
		got := purl.MakePURL(tt.ecosystem, tt.packageName, tt.version)
		if got == nil {
			t.Fatalf("MakePURL(%q, %q, %q) = nil", tt.ecosystem, tt.packageName, tt.version)
		}
		if got.Type != tt.wantType {
			t.Errorf("MakePURL(%q, %q, %q).Type = %q, want %q", tt.ecosystem, tt.packageName, tt.version, got.Type, tt.wantType)
		}
		if got.Namespace != tt.wantNamespace {
			t.Errorf("MakePURL(%q, %q, %q).Namespace = %q, want %q", tt.ecosystem, tt.packageName, tt.version, got.Namespace, tt.wantNamespace)
		}
		if got.Name != tt.wantName {
			t.Errorf("MakePURL(%q, %q, %q).Name = %q, want %q", tt.ecosystem, tt.packageName, tt.version, got.Name, tt.wantName)
		}
		if got.Version != tt.version {
			t.Errorf("MakePURL(%q, %q, %q).Version = %q, want %q", tt.ecosystem, tt.packageName, tt.version, got.Version, tt.version)
		}
	}
}

// vulnerabilities.go:248 compares vulns.Package.Name against p.FullName() on
// a *PURL from MakePURL. vulnerabilities_test.go:62 requires
// MakePURL("npm", "lodash", "4.17.20").FullName() == "lodash" so that
// vulns.Package.Name = "lodash" matches.
func TestMakePURLFullNameNPM(t *testing.T) {
	p := purl.MakePURL("npm", "lodash", "4.17.20")
	if p == nil {
		t.Fatal("MakePURL returned nil")
	}
	if p.Type != "npm" {
		t.Errorf("p.Type = %q, want %q", p.Type, "npm")
	}
	if p.FullName() != "lodash" {
		t.Errorf("p.FullName() = %q, want %q", p.FullName(), "lodash")
	}
	if p.Version != "4.17.20" {
		t.Errorf("p.Version = %q, want %q", p.Version, "4.17.20")
	}
}

// vulnerabilities.go:253 falls back to comparing vulns.Package.Name against
// p.Name (not FullName) when p.Type is "apk" or "alpm".
// vulnerabilities_test.go:164 requires MakePURL("alpine", "openssl", ...).Name
// == "openssl" so vulns.Package.Name = "openssl" matches.
func TestMakePURLNameFieldForAPK(t *testing.T) {
	p := purl.MakePURL("alpine", "openssl", "3.0.8-r0")
	if p == nil {
		t.Fatal("MakePURL returned nil")
	}
	if p.Type != "apk" {
		t.Errorf("p.Type = %q, want %q", p.Type, "apk")
	}
	if p.Name != "openssl" {
		t.Errorf("p.Name = %q, want %q", p.Name, "openssl")
	}
}
