package enrichment

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vers"
	"github.com/git-pkgs/vulns"
	"github.com/git-pkgs/vulns/osv"
)

// ErrUnsupportedVulnerabilityIdentity identifies packages without an identity
// supported by vulnerability lookups, including Swift registry-only packages.
var ErrUnsupportedVulnerabilityIdentity = errors.New("package identity is not supported for vulnerability lookups")

// VulnerabilityQuery identifies a package version to check for vulnerabilities.
type VulnerabilityQuery struct {
	Ecosystem string
	Name      string
	Version   string
}

// VulnerabilityResult contains the vulnerabilities found for a query.
type VulnerabilityResult struct {
	Query           VulnerabilityQuery
	Vulnerabilities []VulnInfo
}

// VulnInfo contains the vulnerability fields most consumers need for display and policy checks.
type VulnInfo struct {
	ID           string
	Summary      string
	Details      string
	Severity     string
	CVSSScore    float64
	CVSSVersion  string
	CVSSVector   string
	FixedVersion string
	References   []string
	Aliases      []string
	Source       string
}

// VulnerabilityClient checks package vulnerabilities using a configured source.
type VulnerabilityClient struct {
	source vulns.Source
}

// VulnerabilityOption configures a VulnerabilityClient.
type VulnerabilityOption func(*vulnerabilityOptions)

type vulnerabilityOptions struct {
	source    vulns.Source
	userAgent string
}

// WithVulnerabilitySource sets the vulnerability data source.
func WithVulnerabilitySource(source vulns.Source) VulnerabilityOption {
	return func(o *vulnerabilityOptions) {
		o.source = source
	}
}

// WithVulnerabilityUserAgent sets the User-Agent for the default OSV source.
func WithVulnerabilityUserAgent(userAgent string) VulnerabilityOption {
	return func(o *vulnerabilityOptions) {
		o.userAgent = userAgent
	}
}

// NewVulnerabilityClient creates a client backed by OSV unless another source is provided.
func NewVulnerabilityClient(opts ...VulnerabilityOption) *VulnerabilityClient {
	o := vulnerabilityOptions{userAgent: defaultUserAgent}
	for _, opt := range opts {
		opt(&o)
	}
	if o.source == nil {
		o.source = osv.New(osv.WithUserAgent(o.userAgent))
	}
	return &VulnerabilityClient{source: o.source}
}

// CheckVulnerabilities checks one package version using the default OSV-backed client.
func CheckVulnerabilities(ctx context.Context, ecosystem, name, version string) ([]VulnInfo, error) {
	return NewVulnerabilityClient().Check(ctx, ecosystem, name, version)
}

// BulkCheckVulnerabilities checks multiple package versions using the default OSV-backed client.
func BulkCheckVulnerabilities(ctx context.Context, queries []VulnerabilityQuery) ([]VulnerabilityResult, error) {
	return NewVulnerabilityClient().CheckBatch(ctx, queries)
}

// Check checks one package version for known vulnerabilities.
func (c *VulnerabilityClient) Check(ctx context.Context, ecosystem, name, version string) ([]VulnInfo, error) {
	p, err := vulnerabilityPURL(ecosystem, name, version)
	if err != nil {
		return nil, err
	}

	found, err := c.source.Query(ctx, p)
	if err != nil {
		return nil, err
	}
	return convertVulnerabilities(found, p, c.source.Name()), nil
}

// CheckBatch checks multiple package versions for known vulnerabilities.
// An unsupported identity rejects the batch before querying the source.
func (c *VulnerabilityClient) CheckBatch(ctx context.Context, queries []VulnerabilityQuery) ([]VulnerabilityResult, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	purls := make([]*purl.PURL, len(queries))
	for i, query := range queries {
		p, err := vulnerabilityPURL(query.Ecosystem, query.Name, query.Version)
		if err != nil {
			return nil, err
		}
		purls[i] = p
	}

	found, err := c.source.QueryBatch(ctx, purls)
	if err != nil {
		return nil, err
	}
	if len(found) != len(purls) {
		return nil, fmt.Errorf("vulnerability source returned %d results for %d queries", len(found), len(purls))
	}

	results := make([]VulnerabilityResult, len(queries))
	for i, vulnsForPackage := range found {
		results[i] = VulnerabilityResult{
			Query:           queries[i],
			Vulnerabilities: convertVulnerabilities(vulnsForPackage, purls[i], c.source.Name()),
		}
	}
	return results, nil
}

func vulnerabilityPURL(ecosystem, name, version string) (*purl.PURL, error) {
	ecosystemInput := ecosystem
	ecosystem = strings.TrimSpace(ecosystem)
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)

	purlType := purl.EcosystemToPURLType(ecosystem)
	if purlType == "" || !isSupportedVulnerabilityEcosystem(ecosystem, purlType) {
		return nil, fmt.Errorf("unsupported ecosystem: %q", ecosystemInput)
	}
	if name == "" {
		return nil, fmt.Errorf("package name is required")
	}
	p := purl.MakePURL(ecosystem, name, version)
	if p == nil {
		return nil, fmt.Errorf("%w: %s package %q", ErrUnsupportedVulnerabilityIdentity, purlType, name)
	}
	if p.Type == "swift" {
		host, _, _ := strings.Cut(p.Namespace, "/")
		if !strings.Contains(host, ".") {
			return nil, fmt.Errorf("%w: Swift registry package %q requires source repository coordinates", ErrUnsupportedVulnerabilityIdentity, name)
		}
	}
	return p, nil
}

func isSupportedVulnerabilityEcosystem(ecosystem, purlType string) bool {
	if purl.IsKnownType(purlType) {
		return true
	}
	for _, supported := range purl.SupportedEcosystems() {
		if purl.NormalizeEcosystem(supported) == purl.NormalizeEcosystem(ecosystem) {
			return true
		}
	}
	return false
}

func convertVulnerabilities(found []vulns.Vulnerability, p *purl.PURL, source string) []VulnInfo {
	if len(found) == 0 {
		return nil
	}

	infos := make([]VulnInfo, 0, len(found))
	for _, v := range found {
		info := VulnInfo{
			ID:           v.ID,
			Summary:      v.Summary,
			Details:      v.Details,
			Severity:     v.SeverityLevel(),
			FixedVersion: fixedVersionForQuery(v, p),
			References:   referenceURLs(v.References),
			Aliases:      v.Aliases,
			Source:       source,
		}
		if cvss := v.CVSS(); cvss != nil {
			info.CVSSScore = cvss.Score
			info.CVSSVersion = cvss.Version
			info.CVSSVector = cvss.Vector
		}
		infos = append(infos, info)
	}
	return infos
}

func fixedVersionForQuery(v vulns.Vulnerability, p *purl.PURL) string {
	if p.Version == "" {
		return v.FixedVersion(p.Type, p.FullName())
	}

	for _, affected := range v.Affected {
		if !matchesAffectedPackage(affected.Package, p) {
			continue
		}
		for _, affectedRange := range affected.Ranges {
			if fixed := fixedVersionForRange(affectedRange, p.Version); fixed != "" {
				return fixed
			}
		}
	}
	return ""
}

func fixedVersionForRange(affectedRange vulns.Range, version string) string {
	if affectedRange.Type != "SEMVER" && affectedRange.Type != "ECOSYSTEM" {
		return ""
	}

	inRange := false
	for _, event := range affectedRange.Events {
		if event.Introduced != "" {
			inRange = event.Introduced == "0" || vers.Compare(version, event.Introduced) >= 0
		}
		if event.Fixed != "" && inRange {
			if vers.Compare(version, event.Fixed) < 0 {
				return event.Fixed
			}
			inRange = false
		}
		if event.LastAffected != "" && inRange && vers.Compare(version, event.LastAffected) > 0 {
			inRange = false
		}
	}
	return ""
}

func matchesAffectedPackage(pkg vulns.Package, p *purl.PURL) bool {
	if pkg.PURL != "" {
		if parsed, err := purl.Parse(pkg.PURL); err == nil {
			return parsed.Type == p.Type && parsed.FullName() == p.FullName()
		}
	}

	if !matchesAffectedPackageName(pkg.Name, p) {
		return false
	}
	return matchesAffectedEcosystem(pkg.Ecosystem, p)
}

func matchesAffectedPackageName(name string, p *purl.PURL) bool {
	if name == p.FullName() {
		return true
	}
	switch p.Type {
	case "apk", "alpm":
		return name == p.Name
	default:
		return false
	}
}

func matchesAffectedEcosystem(ecosystem string, p *purl.PURL) bool {
	candidates := []string{
		p.Type,
		purl.PURLTypeToEcosystem(p.Type),
		purl.EcosystemToOSV(p.Type),
		purl.EcosystemToOSV(purl.PURLTypeToEcosystem(p.Type)),
	}
	for _, candidate := range candidates {
		if strings.EqualFold(ecosystem, candidate) {
			return true
		}
		if purl.NormalizeEcosystem(ecosystem) == purl.NormalizeEcosystem(candidate) {
			return true
		}
	}
	return false
}

func referenceURLs(refs []vulns.Reference) []string {
	if len(refs) == 0 {
		return nil
	}
	urls := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.URL != "" {
			urls = append(urls, ref.URL)
		}
	}
	return urls
}
