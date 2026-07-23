package enrichment

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ecosyste-ms/ecosystems-go"
	"github.com/ecosyste-ms/ecosystems-go/packages"
	"github.com/git-pkgs/registries"
)

// EcosystemsClient wraps the ecosyste.ms API client.
type EcosystemsClient struct {
	client *ecosystems.Client
}

// NewEcosystemsClient creates a client that uses the ecosyste.ms API.
func NewEcosystemsClient() (*EcosystemsClient, error) {
	return newEcosystemsClient(options{userAgent: defaultUserAgent})
}

func newEcosystemsClient(o options) (*EcosystemsClient, error) {
	clientOpts := []ecosystems.Option{}
	if o.from != "" {
		clientOpts = append(clientOpts, ecosystems.WithFrom(o.from))
	}
	if o.apiKey != "" {
		clientOpts = append(clientOpts, ecosystems.WithAPIKey(o.apiKey))
	}
	if o.batchSize > 0 {
		clientOpts = append(clientOpts, ecosystems.WithBatchSize(o.batchSize))
	}

	client, err := ecosystems.NewClient(o.userAgent, clientOpts...)
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

		// Popularity and usage
		info.Downloads = pkg.Downloads
		if pkg.DownloadsPeriod != nil {
			info.DownloadsPeriod = *pkg.DownloadsPeriod
		}
		info.DependentPackagesCount = pkg.DependentPackagesCount
		info.DependentReposCount = pkg.DependentReposCount

		info.Advisories = convertAdvisories(pkg.Advisories)
		info.FundingLinks = pkg.FundingLinks
		info.Maintainers = convertMaintainers(pkg.Maintainers)

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
		result = append(result, versionInfoFromEcosystems(
			v.Number,
			v.PublishedAt,
			v.Integrity,
			v.Licenses,
			v.Status,
			v.Metadata,
		))
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

	info := versionInfoFromEcosystems(
		v.Number,
		v.PublishedAt,
		v.Integrity,
		v.Licenses,
		v.Status,
		v.Metadata,
	)
	return &info, nil
}

func versionInfoFromEcosystems(
	number string,
	publishedAt, integrity, license, status *string,
	metadata *map[string]any,
) VersionInfo {
	info := VersionInfo{Number: number}
	if publishedAt != nil {
		info.PublishedAt, _ = time.Parse(time.RFC3339, *publishedAt)
	}
	if integrity != nil {
		info.Integrity = *integrity
	}
	if license != nil {
		info.License = *license
	}
	if status != nil {
		info.Status = *status
		info.Yanked = info.Status == string(registries.StatusYanked)
	}
	if metadata != nil {
		info.Metadata = *metadata
	}
	return info
}

// GetDependentsByRepositoryURL finds packages published from repositoryURL and
// fetches dependent packages for each of them.
func (c *EcosystemsClient) GetDependentsByRepositoryURL(ctx context.Context, repositoryURL string, maxPackages, maxDependentsPerPackage int) ([]RepositoryDependents, error) {
	pkgs, err := c.client.LookupPackagesByRepositoryURL(ctx, repositoryURL, maxPackages)
	if err != nil {
		return nil, err
	}
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name == pkgs[j].Name {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		return pkgs[i].Name < pkgs[j].Name
	})

	result := make([]RepositoryDependents, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg.Registry.Name == "" {
			return nil, fmt.Errorf("package %s has no registry name", pkg.Name)
		}
		dependents, err := c.client.GetDependentPackages(ctx, pkg.Registry.Name, pkg.Name, maxDependentsPerPackage)
		if err != nil {
			return nil, fmt.Errorf("get dependents for %s/%s: %w", pkg.Registry.Name, pkg.Name, err)
		}
		out := make([]DependentPackage, 0, len(dependents))
		for _, dep := range dependents {
			out = append(out, convertDependentPackage(dep))
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Name == out[j].Name {
				return out[i].PURL < out[j].PURL
			}
			return out[i].Name < out[j].Name
		})
		result = append(result, RepositoryDependents{
			PackageName: pkg.Name,
			Ecosystem:   pkg.Ecosystem,
			PURL:        pkg.Purl,
			Dependents:  out,
		})
	}
	return result, nil
}

func convertDependentPackage(pkg packages.Package) DependentPackage {
	out := DependentPackage{
		Ecosystem:           pkg.Ecosystem,
		Name:                pkg.Name,
		PURL:                pkg.Purl,
		Downloads:           pkg.Downloads,
		DependentReposCount: pkg.DependentReposCount,
	}
	if pkg.RepositoryUrl != nil {
		out.Repository = *pkg.RepositoryUrl
	}
	if out.Repository == "" {
		out.Repository = extractRepoHTMLURL(pkg.RepoMetadata)
	}
	if pkg.RegistryUrl != nil {
		out.RegistryURL = *pkg.RegistryUrl
	} else {
		out.RegistryURL = registries.DefaultURL(pkg.Ecosystem)
	}
	if pkg.LatestReleaseNumber != nil {
		out.LatestVersion = *pkg.LatestReleaseNumber
	}
	return out
}

func extractRepoHTMLURL(repoMetadata *map[string]interface{}) string {
	if repoMetadata == nil {
		return ""
	}
	if htmlURL, ok := (*repoMetadata)["html_url"].(string); ok {
		return htmlURL
	}
	return ""
}

func convertMaintainers(maintainers []packages.Maintainer) []Maintainer {
	if len(maintainers) == 0 {
		return nil
	}
	result := make([]Maintainer, 0, len(maintainers))
	for _, m := range maintainers {
		out := Maintainer{}
		if m.Login != nil {
			out.Login = *m.Login
		}
		if m.Name != nil {
			out.Name = *m.Name
		}
		if m.Email != nil {
			out.Email = *m.Email
		}
		if m.HtmlUrl != nil {
			out.URL = *m.HtmlUrl
		}
		if m.Role != nil {
			out.Role = *m.Role
		}
		result = append(result, out)
	}
	return result
}

func convertAdvisories(advisories []packages.Advisory) []Advisory {
	if len(advisories) == 0 {
		return nil
	}
	result := make([]Advisory, 0, len(advisories))
	for _, adv := range advisories {
		a := Advisory{
			Identifiers: adv.Identifiers,
		}
		if adv.Title != nil {
			a.Title = *adv.Title
		}
		if adv.Severity != nil {
			a.Severity = *adv.Severity
		}
		if adv.CvssScore != nil {
			a.CVSSScore = *adv.CvssScore
		}
		if adv.Url != nil {
			a.URL = *adv.Url
		}
		result = append(result, a)
	}
	return result
}
