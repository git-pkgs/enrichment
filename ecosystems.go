package enrichment

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ecosyste-ms/ecosystems-go"
	"github.com/ecosyste-ms/ecosystems-go/packages"
	"github.com/git-pkgs/registries"
	"github.com/oapi-codegen/nullable"
)

// nullableValue returns the underlying value of n, or the zero value of T if n
// is null or unspecified.
func nullableValue[T any](n nullable.Nullable[T]) T {
	v, _ := n.Get()
	return v
}

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
		info.LatestVersion = nullableValue(pkg.LatestReleaseNumber)
		if len(pkg.NormalizedLicenses) > 0 {
			info.License = pkg.NormalizedLicenses[0]
		} else if licenses := nullableValue(pkg.Licenses); licenses != "" {
			info.License = licenses
		}
		info.Description = nullableValue(pkg.Description)
		info.Homepage = nullableValue(pkg.Homepage)
		info.Repository = nullableValue(pkg.RepositoryURL)
		info.ChangelogFilename = extractChangelogFilename(nullableValue(pkg.RepoMetadata))

		// Popularity and usage
		info.Downloads = pkg.Downloads
		info.DownloadsPeriod = nullableValue(pkg.DownloadsPeriod)
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
func extractChangelogFilename(repoMetadata map[string]interface{}) string {
	metadataRaw, ok := repoMetadata["metadata"]
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
	publishedAt, integrity, license, status nullable.Nullable[string],
	metadata nullable.Nullable[map[string]any],
) VersionInfo {
	info := VersionInfo{Number: number}
	if pub := nullableValue(publishedAt); pub != "" {
		info.PublishedAt, _ = time.Parse(time.RFC3339, pub)
	}
	info.Integrity = nullableValue(integrity)
	info.License = nullableValue(license)
	if s, err := status.Get(); err == nil {
		info.Status = s
		info.Yanked = info.Status == string(registries.StatusYanked)
	}
	info.Metadata = nullableValue(metadata)
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
			PURL:        pkg.PURL,
			Dependents:  out,
		})
	}
	return result, nil
}

func convertDependentPackage(pkg packages.Package) DependentPackage {
	out := DependentPackage{
		Ecosystem:           pkg.Ecosystem,
		Name:                pkg.Name,
		PURL:                pkg.PURL,
		Downloads:           pkg.Downloads,
		DependentReposCount: pkg.DependentReposCount,
	}
	out.Repository = nullableValue(pkg.RepositoryURL)
	if out.Repository == "" {
		out.Repository = extractRepoHTMLURL(nullableValue(pkg.RepoMetadata))
	}
	if registryURL, err := pkg.RegistryURL.Get(); err == nil {
		out.RegistryURL = registryURL
	} else {
		out.RegistryURL = registries.DefaultURL(pkg.Ecosystem)
	}
	out.LatestVersion = nullableValue(pkg.LatestReleaseNumber)
	return out
}

func extractRepoHTMLURL(repoMetadata map[string]interface{}) string {
	if htmlURL, ok := repoMetadata["html_url"].(string); ok {
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
		result = append(result, Maintainer{
			Login: nullableValue(m.Login),
			Name:  nullableValue(m.Name),
			Email: nullableValue(m.Email),
			URL:   nullableValue(m.HTMLURL),
			Role:  nullableValue(m.Role),
		})
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
			Title:     nullableValue(adv.Title),
			Severity:  nullableValue(adv.Severity),
			CVSSScore: nullableValue(adv.CVSSScore),
			URL:       nullableValue(adv.URL),
		}
		for _, id := range adv.Identifiers {
			if v := nullableValue(id); v != "" {
				a.Identifiers = append(a.Identifiers, v)
			}
		}
		result = append(result, a)
	}
	return result
}
