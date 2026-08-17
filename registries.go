package enrichment

import (
	"context"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
	"github.com/git-pkgs/registries/client"
)

// RegistriesClient queries package registries directly.
type RegistriesClient struct {
	client *registries.Client
}

// NewRegistriesClient creates a client that queries registries directly.
func NewRegistriesClient() *RegistriesClient {
	return newRegistriesClient(defaultUserAgent)
}

func newRegistriesClient(userAgent string) *RegistriesClient {
	// PURLs may carry an attacker-supplied repository_url qualifier that
	// NewFromPURL/BulkFetchPackages will fetch from; gate the client's
	// transport so loopback/RFC1918/link-local targets are refused.
	c := registries.NewClient(client.WithSafeHTTP())
	c.UserAgent = userAgent
	return &RegistriesClient{client: c}
}

func (c *RegistriesClient) BulkLookup(ctx context.Context, purls []string) (map[string]*PackageInfo, error) {
	packages := registries.BulkFetchPackages(ctx, purls, c.client)

	// For packages without LatestVersion populated, use registries' shared
	// latest-release policy.
	var needLatest []string
	for purlStr, pkg := range packages {
		if pkg != nil && pkg.LatestVersion == "" {
			needLatest = append(needLatest, purlStr)
		}
	}

	latestVersions := registries.BulkFetchLatestVersions(ctx, needLatest, c.client)

	result := make(map[string]*PackageInfo, len(packages))
	for purlStr, pkg := range packages {
		if pkg == nil {
			continue
		}

		ecosystem := purlType(purlStr)

		info := &PackageInfo{
			Ecosystem:     ecosystem,
			Name:          pkg.Name,
			LatestVersion: pkg.LatestVersion,
			License:       pkg.Licenses,
			Description:   pkg.Description,
			Homepage:      pkg.Homepage,
			Repository:    pkg.Repository,
			RegistryURL:   extractRegistryURL(purlStr, ecosystem),
			Source:        "registries",
		}

		if info.LatestVersion == "" {
			if latest := latestVersions[purlStr]; latest != nil {
				info.LatestVersion = latest.Number
			}
		}

		result[purlStr] = info
	}
	return result, nil
}

func purlType(purlStr string) string {
	p, err := purl.Parse(purlStr)
	if err != nil || p == nil {
		return ""
	}
	return p.Type
}

func (c *RegistriesClient) GetVersions(ctx context.Context, purlStr string) ([]VersionInfo, error) {
	reg, name, _, err := registries.NewFromPURL(purlStr, c.client)
	if err != nil {
		return nil, err
	}

	versions, err := reg.FetchVersions(ctx, name)
	if err != nil {
		return nil, err
	}

	result := make([]VersionInfo, 0, len(versions))
	for _, v := range versions {
		result = append(result, versionInfoFromRegistry(v))
	}
	return result, nil
}

func (c *RegistriesClient) GetVersion(ctx context.Context, purlStr string) (*VersionInfo, error) {
	v, err := registries.FetchVersionFromPURL(ctx, purlStr, c.client)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}

	info := versionInfoFromRegistry(*v)
	return &info, nil
}

func versionInfoFromRegistry(v registries.Version) VersionInfo {
	return VersionInfo{
		Number:      v.Number,
		PublishedAt: v.PublishedAt,
		Integrity:   v.Integrity,
		License:     v.Licenses,
		Status:      string(v.Status),
		Yanked:      v.Status == registries.StatusYanked,
		Metadata:    v.Metadata,
	}
}

// extractRegistryURL extracts the registry URL from a PURL qualifier or returns the default.
func extractRegistryURL(purlStr, ecosystem string) string {
	p, err := purl.Parse(purlStr)
	if err != nil {
		return registries.DefaultURL(ecosystem)
	}
	if url := p.Qualifier("repository_url"); url != "" {
		return url
	}
	return registries.DefaultURL(ecosystem)
}
