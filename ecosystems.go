package enrichment

import (
	"context"
	"time"

	"github.com/ecosyste-ms/ecosystems-go"
	"github.com/git-pkgs/registries"
)

// EcosystemsClient wraps the ecosyste.ms API client.
type EcosystemsClient struct {
	client *ecosystems.Client
}

// NewEcosystemsClient creates a client that uses the ecosyste.ms API.
func NewEcosystemsClient() (*EcosystemsClient, error) {
	return newEcosystemsClient(defaultUserAgent)
}

func newEcosystemsClient(userAgent string) (*EcosystemsClient, error) {
	client, err := ecosystems.NewClient(userAgent)
	if err != nil {
		return nil, err
	}
	return &EcosystemsClient{client: client}, nil
}

func (c *EcosystemsClient) BulkLookup(ctx context.Context, purls []string) (map[string]*PackageInfo, error) {
	packages, err := c.client.BulkLookup(ctx, purls)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*PackageInfo, len(packages))
	for purlStr, pkg := range packages {
		if pkg == nil {
			continue
		}

		info := &PackageInfo{
			Ecosystem:   pkg.Ecosystem,
			Name:        pkg.Name,
			RegistryURL: registries.DefaultURL(pkg.Ecosystem),
			Source:      "ecosystems",
		}
		if pkg.LatestReleaseNumber != nil {
			info.LatestVersion = *pkg.LatestReleaseNumber
		}
		if len(pkg.NormalizedLicenses) > 0 {
			info.License = pkg.NormalizedLicenses[0]
		} else if pkg.Licenses != nil && *pkg.Licenses != "" {
			info.License = *pkg.Licenses
		}
		if pkg.Description != nil {
			info.Description = *pkg.Description
		}
		if pkg.Homepage != nil {
			info.Homepage = *pkg.Homepage
		}
		if pkg.RepositoryUrl != nil {
			info.Repository = *pkg.RepositoryUrl
		}
		info.ChangelogFilename = extractChangelogFilename(pkg.RepoMetadata)
		result[purlStr] = info
	}
	return result, nil
}

// extractChangelogFilename digs into the ecosyste.ms RepoMetadata to find the
// changelog filename at metadata.files.changelog.
func extractChangelogFilename(repoMetadata *map[string]interface{}) string {
	if repoMetadata == nil {
		return ""
	}
	meta := *repoMetadata
	metadataRaw, ok := meta["metadata"]
	if !ok {
		return ""
	}
	metadata, ok := metadataRaw.(map[string]interface{})
	if !ok {
		return ""
	}
	filesRaw, ok := metadata["files"]
	if !ok {
		return ""
	}
	files, ok := filesRaw.(map[string]interface{})
	if !ok {
		return ""
	}
	filename, ok := files["changelog"].(string)
	if !ok {
		return ""
	}
	return filename
}

func (c *EcosystemsClient) GetVersions(ctx context.Context, purlStr string) ([]VersionInfo, error) {
	p, err := ecosystems.ParsePURL(purlStr)
	if err != nil {
		return nil, err
	}

	versions, err := c.client.GetAllVersionsPURL(ctx, p)
	if err != nil {
		return nil, err
	}

	result := make([]VersionInfo, 0, len(versions))
	for _, v := range versions {
		info := VersionInfo{Number: v.Number}
		if v.PublishedAt != nil {
			info.PublishedAt, _ = time.Parse(time.RFC3339, *v.PublishedAt)
		}
		result = append(result, info)
	}
	return result, nil
}

func (c *EcosystemsClient) GetVersion(ctx context.Context, purlStr string) (*VersionInfo, error) {
	p, err := ecosystems.ParsePURL(purlStr)
	if err != nil {
		return nil, err
	}

	v, err := c.client.GetVersionPURL(ctx, p)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, nil
	}

	info := &VersionInfo{Number: v.Number}
	if v.PublishedAt != nil {
		info.PublishedAt, _ = time.Parse(time.RFC3339, *v.PublishedAt)
	}
	if v.Integrity != nil {
		info.Integrity = *v.Integrity
	}
	return info, nil
}
