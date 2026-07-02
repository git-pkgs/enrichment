package enrichment

import (
	"strings"

	"github.com/git-pkgs/spdx"
	"github.com/git-pkgs/vers"
)

// LicenseCategory describes the broad policy category for a license expression.
type LicenseCategory string

const (
	// LicenseCategoryPermissive is used when every license in the expression is permissive.
	LicenseCategoryPermissive LicenseCategory = "permissive"
	// LicenseCategoryCopyleft is used when the expression contains a copyleft license.
	LicenseCategoryCopyleft LicenseCategory = "copyleft"
	// LicenseCategoryUnknown is used when the expression cannot be classified.
	LicenseCategoryUnknown LicenseCategory = "unknown"
)

// CategorizeLicense classifies a license expression as permissive, copyleft, or unknown.
// This is intentionally conservative: any copyleft license in an expression
// makes the whole expression copyleft, including OR expressions.
func CategorizeLicense(license string) LicenseCategory {
	license = strings.TrimSpace(license)
	if license == "" {
		return LicenseCategoryUnknown
	}

	normalized, err := spdx.NormalizeExpressionLax(license)
	if err != nil {
		return LicenseCategoryUnknown
	}

	if spdx.HasCopyleft(normalized) {
		return LicenseCategoryCopyleft
	}
	if spdx.IsFullyPermissive(normalized) {
		return LicenseCategoryPermissive
	}
	return LicenseCategoryUnknown
}

// IsOutdated reports whether current is older than latest.
func IsOutdated(current, latest string) bool {
	current = strings.TrimSpace(current)
	latest = strings.TrimSpace(latest)
	if current == "" || latest == "" {
		return false
	}
	return vers.Compare(current, latest) < 0
}
