// Package enrichment provides a unified interface for fetching package metadata
// from external sources (ecosyste.ms API, direct registry queries, deps.dev).
package enrichment

import (
	"context"
	"time"
)

// Client fetches package metadata from external sources.
type Client interface {
	// BulkLookup fetches metadata for multiple packages by PURL.
	// Returns a map of PURL to PackageInfo. Missing packages are omitted.
	BulkLookup(ctx context.Context, purls []string) (map[string]*PackageInfo, error)

	// GetVersions fetches all versions for a package.
	// The purl should be a package PURL without version (pkg:npm/lodash).
	GetVersions(ctx context.Context, purl string) ([]VersionInfo, error)

	// GetVersion fetches metadata for a specific version.
	// The purl must include a version (pkg:npm/lodash@4.17.21).
	GetVersion(ctx context.Context, purl string) (*VersionInfo, error)
}

// PackageInfo contains metadata about a package.
type PackageInfo struct {
	Ecosystem         string
	Name              string
	LatestVersion     string
	License           string
	Description       string
	Homepage          string
	Repository        string
	RegistryURL       string
	ChangelogFilename string
	Source            string // "ecosystems", "registries", or "depsdev"

	// Popularity and usage (ecosyste.ms only)
	Downloads              int
	DownloadsPeriod        string // e.g. "last-month"
	DependentPackagesCount int
	DependentReposCount    int

	// Security advisories (ecosyste.ms only)
	Advisories []Advisory

	// Funding and maintainers (ecosyste.ms only)
	FundingLinks []string
	Maintainers  []Maintainer
}

// RepositoryDependents groups dependent packages by one package published from
// a source repository.
type RepositoryDependents struct {
	PackageName string
	Ecosystem   string
	PURL        string
	Dependents  []DependentPackage
}

// DependentPackage contains metadata for one package that depends on another.
type DependentPackage struct {
	Ecosystem           string
	Name                string
	PURL                string
	Repository          string
	RepositoryMetadata  RepositoryMetadata
	RegistryURL         string
	LatestVersion       string
	Downloads           int
	DependentReposCount int
}

// RepositoryMetadata contains repository details used to filter and rank
// dependent packages.
type RepositoryMetadata struct {
	Fork            bool
	Archived        bool
	MirrorURL       string
	SourceName      string
	PushedAt        time.Time
	StargazersCount int
	Language        string
}

// Maintainer is a person or account that maintains a package on its registry.
type Maintainer struct {
	Login string
	Name  string
	Email string
	URL   string
	Role  string
}

// Advisory is a security advisory affecting a package.
type Advisory struct {
	Title       string
	Severity    string // e.g. "critical", "high", "medium", "low"
	CVSSScore   float32
	URL         string
	Identifiers []string // CVE IDs and other identifiers
}

// VersionInfo contains metadata about a specific version.
type VersionInfo struct {
	Number      string
	PublishedAt time.Time
	Integrity   string
	License     string
	Status      string         // registry-defined status, such as "yanked", "deprecated", or "retracted"
	Yanked      bool           // true when Status is "yanked"; retained for compatibility
	Metadata    map[string]any // registry-specific version metadata
}
