package enrichment

import (
	"context"
	"fmt"
	"strings"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vulns"
	"github.com/git-pkgs/vulns/osv"
)

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
	ecosystem = strings.TrimSpace(ecosystem)
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)

	purlType := purl.EcosystemToPURLType(ecosystem)
	if purlType == "" {
		purlType = purl.NormalizeEcosystem(ecosystem)
	}
	if purlType == "" || name == "" {
		return nil, fmt.Errorf("ecosystem and name are required")
	}
	return purl.MakePURL(purlType, name, version), nil
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
			FixedVersion: v.FixedVersion(p.Type, p.FullName()),
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
