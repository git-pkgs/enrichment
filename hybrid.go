package enrichment

import (
	"context"
	"sync"

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
	return newHybridClient(options{userAgent: defaultUserAgent})
}

func newHybridClient(o options) (*HybridClient, error) {
	eco, err := newEcosystemsClient(o)
	if err != nil {
		return nil, err
	}
	return &HybridClient{
		ecosystems: eco,
		registries: newRegistriesClient(o.userAgent),
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

	var (
		ecoResults, regResults map[string]*PackageInfo
		ecoErr, regErr         error
	)

	if len(ecoPurls) > 0 && len(regPurls) > 0 {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			ecoResults, ecoErr = c.ecosystems.BulkLookup(ctx, ecoPurls)
		}()
		go func() {
			defer wg.Done()
			regResults, regErr = c.registries.BulkLookup(ctx, regPurls)
		}()
		wg.Wait()
	} else if len(ecoPurls) > 0 {
		ecoResults, ecoErr = c.ecosystems.BulkLookup(ctx, ecoPurls)
	} else if len(regPurls) > 0 {
		regResults, regErr = c.registries.BulkLookup(ctx, regPurls)
	}

	if ecoErr != nil {
		return nil, ecoErr
	}
	if regErr != nil {
		return nil, regErr
	}

	result := make(map[string]*PackageInfo)
	for purlStr, info := range ecoResults {
		result[purlStr] = info
	}
	for purlStr, info := range regResults {
		result[purlStr] = info
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
