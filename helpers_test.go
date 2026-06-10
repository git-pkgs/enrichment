package enrichment

import "testing"

func TestCategorizeLicense(t *testing.T) {
	tests := []struct {
		name    string
		license string
		want    LicenseCategory
	}{
		{"permissive identifier", "MIT", LicenseCategoryPermissive},
		{"permissive expression", "MIT OR Apache-2.0", LicenseCategoryPermissive},
		{"informal permissive", "MIT License", LicenseCategoryPermissive},
		{"copyleft identifier", "GPL-3.0-only", LicenseCategoryCopyleft},
		{"copyleft expression", "MIT AND GPL-2.0-only", LicenseCategoryCopyleft},
		{"empty", "", LicenseCategoryUnknown},
		{"invalid", "not-a-license", LicenseCategoryUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CategorizeLicense(tt.license); got != tt.want {
				t.Errorf("CategorizeLicense(%q) = %q, want %q", tt.license, got, tt.want)
			}
		})
	}
}

func TestIsOutdated(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"1.0.0", "1.0.1", true},
		{"1.0.1", "1.0.1", false},
		{"1.0.2", "1.0.1", false},
		{"", "1.0.1", false},
		{"1.0.0", "", false},
		{" v1.0.0 ", "1.0.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.current+"_"+tt.latest, func(t *testing.T) {
			if got := IsOutdated(tt.current, tt.latest); got != tt.want {
				t.Errorf("IsOutdated(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}
