package enrichment

import (
	"context"

	"github.com/git-pkgs/purl"
)

// HybridClient routes requests based on PURL qualifiers.
// PURLs with repository_url go to registries, others go to ecosyste.ms.
type HybridClient struct {
	ecosystems *EcosystemsClient
	registries *RegistriesClient
}

// NewHybridClient creates a client that routes based on PURL qualifiers.
func NewHybridClient() (*HybridClient, error) {
	return newHybridClient(defaultUserAgent)
}

func newHybridClient(userAgent string) (*HybridClient, error) {
	eco, err := newEcosystemsClient(userAgent)
	if err != nil {
		return nil, err
	}
	return &HybridClient{
		ecosystems: eco,
		registries: newRegistriesClient(userAgent),
	}, nil
}

func (c *HybridClient) BulkLookup(ctx context.Context, purls []string) (map[string]*PackageInfo, error) {
	var ecoPurls, regPurls []string

	for _, purlStr := range purls {
		if hasRepositoryURL(purlStr) {
			regPurls = append(regPurls, purlStr)
		} else {
			ecoPurls = append(ecoPurls, purlStr)
		}
	}

	result := make(map[string]*PackageInfo)

	if len(ecoPurls) > 0 {
		ecoResults, err := c.ecosystems.BulkLookup(ctx, ecoPurls)
		if err != nil {
			return nil, err
		}
		for purlStr, info := range ecoResults {
			result[purlStr] = info
		}
	}

	if len(regPurls) > 0 {
		regResults, err := c.registries.BulkLookup(ctx, regPurls)
		if err != nil {
			for purlStr, info := range regResults {
				result[purlStr] = info
			}
		} else {
			for purlStr, info := range regResults {
				result[purlStr] = info
			}
		}
	}

	return result, nil
}

func (c *HybridClient) GetVersions(ctx context.Context, purlStr string) ([]VersionInfo, error) {
	if hasRepositoryURL(purlStr) {
		return c.registries.GetVersions(ctx, purlStr)
	}
	return c.ecosystems.GetVersions(ctx, purlStr)
}

func (c *HybridClient) GetVersion(ctx context.Context, purlStr string) (*VersionInfo, error) {
	if hasRepositoryURL(purlStr) {
		return c.registries.GetVersion(ctx, purlStr)
	}
	return c.ecosystems.GetVersion(ctx, purlStr)
}

// hasRepositoryURL checks if a PURL has a repository_url qualifier.
func hasRepositoryURL(purlStr string) bool {
	p, err := purl.Parse(purlStr)
	if err != nil {
		return false
	}
	return p.Qualifier("repository_url") != ""
}
