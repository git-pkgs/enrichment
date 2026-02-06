package enrichment

import (
	"context"
	"sync"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
	"github.com/git-pkgs/vers"
)

// RegistriesClient queries package registries directly.
type RegistriesClient struct {
	client *registries.Client
}

// NewRegistriesClient creates a client that queries registries directly.
func NewRegistriesClient() *RegistriesClient {
	return &RegistriesClient{
		client: registries.DefaultClient(),
	}
}

func (c *RegistriesClient) BulkLookup(ctx context.Context, purls []string) (map[string]*PackageInfo, error) {
	packages := registries.BulkFetchPackages(ctx, purls, c.client)

	// For packages without LatestVersion populated, fetch versions and compute it
	var needLatest []string
	for purlStr, pkg := range packages {
		if pkg != nil && pkg.LatestVersion == "" {
			needLatest = append(needLatest, purlStr)
		}
	}

	latestVersions := make(map[string]string)
	if len(needLatest) > 0 {
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 10)

		for _, purlStr := range needLatest {
			wg.Add(1)
			go func(purlStr string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				versions, err := c.GetVersions(ctx, purlStr)
				if err != nil || len(versions) == 0 {
					return
				}
				latest := findLatestVersion(versions)
				mu.Lock()
				latestVersions[purlStr] = latest
				mu.Unlock()
			}(purlStr)
		}
		wg.Wait()
	}

	result := make(map[string]*PackageInfo, len(packages))
	for purlStr, pkg := range packages {
		if pkg == nil {
			continue
		}

		p, _ := purl.Parse(purlStr)
		ecosystem := ""
		if p != nil {
			ecosystem = p.Type
		}

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
			info.LatestVersion = latestVersions[purlStr]
		}

		result[purlStr] = info
	}
	return result, nil
}

// findLatestVersion returns the highest version from a list using semver comparison.
func findLatestVersion(versions []VersionInfo) string {
	if len(versions) == 0 {
		return ""
	}
	latest := versions[0].Number
	for _, v := range versions[1:] {
		if vers.Compare(v.Number, latest) > 0 {
			latest = v.Number
		}
	}
	return latest
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
		info := VersionInfo{
			Number:      v.Number,
			PublishedAt: v.PublishedAt,
			Integrity:   v.Integrity,
			License:     v.Licenses,
		}
		result = append(result, info)
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

	return &VersionInfo{
		Number:      v.Number,
		PublishedAt: v.PublishedAt,
		Integrity:   v.Integrity,
		License:     v.Licenses,
	}, nil
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
