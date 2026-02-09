package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/git-pkgs/purl"
)

// DepsDevClient queries the deps.dev v3 REST API.
type DepsDevClient struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

// NewDepsDevClient creates a client for the deps.dev API.
func NewDepsDevClient() *DepsDevClient {
	return newDepsDevClient(defaultUserAgent)
}

func newDepsDevClient(userAgent string) *DepsDevClient {
	return &DepsDevClient{
		baseURL: "https://api.deps.dev",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		userAgent: userAgent,
	}
}

func (c *DepsDevClient) BulkLookup(ctx context.Context, purls []string) (map[string]*PackageInfo, error) {
	result := make(map[string]*PackageInfo, len(purls))

	for _, purlStr := range purls {
		p, err := purl.Parse(purlStr)
		if err != nil {
			continue
		}

		system := purl.PURLTypeToDepsdev(p.Type)
		if system == "" {
			continue
		}

		name := p.FullName()
		resp, err := c.getPackage(ctx, system, name)
		if err != nil {
			continue
		}

		info := &PackageInfo{
			Ecosystem: p.Type,
			Name:      name,
			Source:    "depsdev",
		}

		for _, v := range resp.Versions {
			if v.IsDefault {
				info.LatestVersion = v.VersionKey.Version
				break
			}
		}

		// Fetch version details for the latest to get license and links
		if info.LatestVersion != "" {
			vResp, err := c.getVersion(ctx, system, name, info.LatestVersion)
			if err == nil {
				if len(vResp.Licenses) > 0 {
					info.License = strings.Join(vResp.Licenses, " AND ")
				}
				for _, link := range vResp.Links {
					switch link.Label {
					case "HOMEPAGE":
						info.Homepage = link.URL
					case "SOURCE_REPO":
						info.Repository = link.URL
					case "ORIGIN":
						info.RegistryURL = link.URL
					}
				}
			}
		}

		result[purlStr] = info
	}

	return result, nil
}

func (c *DepsDevClient) GetVersions(ctx context.Context, purlStr string) ([]VersionInfo, error) {
	p, err := purl.Parse(purlStr)
	if err != nil {
		return nil, err
	}

	system := purl.PURLTypeToDepsdev(p.Type)
	if system == "" {
		return nil, fmt.Errorf("unsupported purl type: %s", p.Type)
	}

	resp, err := c.getPackage(ctx, system, p.FullName())
	if err != nil {
		return nil, err
	}

	result := make([]VersionInfo, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		info := VersionInfo{
			Number: v.VersionKey.Version,
		}
		if v.PublishedAt != "" {
			info.PublishedAt, _ = time.Parse(time.RFC3339, v.PublishedAt)
		}
		result = append(result, info)
	}
	return result, nil
}

func (c *DepsDevClient) GetVersion(ctx context.Context, purlStr string) (*VersionInfo, error) {
	p, err := purl.Parse(purlStr)
	if err != nil {
		return nil, err
	}

	system := purl.PURLTypeToDepsdev(p.Type)
	if system == "" {
		return nil, fmt.Errorf("unsupported purl type: %s", p.Type)
	}

	resp, err := c.getVersion(ctx, system, p.FullName(), p.Version)
	if err != nil {
		return nil, err
	}

	info := &VersionInfo{
		Number: resp.VersionKey.Version,
	}
	if resp.PublishedAt != "" {
		info.PublishedAt, _ = time.Parse(time.RFC3339, resp.PublishedAt)
	}
	if len(resp.Licenses) > 0 {
		info.License = strings.Join(resp.Licenses, " AND ")
	}
	return info, nil
}

type depsdevPackageResponse struct {
	PackageKey struct {
		System string `json:"system"`
		Name   string `json:"name"`
	} `json:"packageKey"`
	Versions []depsdevVersion `json:"versions"`
}

type depsdevVersion struct {
	VersionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	PublishedAt string `json:"publishedAt"`
	IsDefault   bool   `json:"isDefault"`
}

type depsdevVersionResponse struct {
	VersionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"versionKey"`
	PublishedAt string   `json:"publishedAt"`
	IsDefault   bool     `json:"isDefault"`
	Licenses    []string `json:"licenses"`
	Links       []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"links"`
}

func (c *DepsDevClient) getPackage(ctx context.Context, system, name string) (*depsdevPackageResponse, error) {
	u := fmt.Sprintf("%s/v3/systems/%s/packages/%s", c.baseURL, system, url.PathEscape(name))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deps.dev: %s", resp.Status)
	}

	var result depsdevPackageResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *DepsDevClient) getVersion(ctx context.Context, system, name, version string) (*depsdevVersionResponse, error) {
	u := fmt.Sprintf("%s/v3/systems/%s/packages/%s/versions/%s",
		c.baseURL, system, url.PathEscape(name), url.PathEscape(version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deps.dev: %s", resp.Status)
	}

	var result depsdevVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

