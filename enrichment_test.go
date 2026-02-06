package enrichment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractRegistryURL(t *testing.T) {
	tests := []struct {
		purl      string
		ecosystem string
		wantCustom bool
	}{
		{"pkg:npm/lodash", "npm", false},
		{"pkg:npm/%40mycompany/utils?repository_url=https://npm.mycompany.com", "npm", true},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			got := extractRegistryURL(tt.purl, tt.ecosystem)
			if tt.wantCustom && got != "https://npm.mycompany.com" {
				t.Errorf("got %q, want custom registry URL", got)
			}
			if !tt.wantCustom && got == "" {
				t.Error("expected default registry URL, got empty")
			}
		})
	}
}

func TestNewClientDefault(t *testing.T) {
	t.Setenv("GIT_PKGS_DIRECT", "")

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if _, ok := client.(*HybridClient); !ok {
		t.Errorf("expected *HybridClient, got %T", client)
	}
}

func TestNewClientDirect(t *testing.T) {
	t.Setenv("GIT_PKGS_DIRECT", "1")

	client, err := NewClient()
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	if _, ok := client.(*RegistriesClient); !ok {
		t.Errorf("expected *RegistriesClient, got %T", client)
	}
}

func TestDirectMode(t *testing.T) {
	t.Setenv("GIT_PKGS_DIRECT", "")

	if directMode() {
		t.Error("directMode() should be false with no env var set")
	}

	t.Setenv("GIT_PKGS_DIRECT", "1")
	if !directMode() {
		t.Error("directMode() should be true with GIT_PKGS_DIRECT=1")
	}

	t.Setenv("GIT_PKGS_DIRECT", "yes")
	if !directMode() {
		t.Error("directMode() should be true with GIT_PKGS_DIRECT=yes")
	}
}

func TestHasRepositoryURL(t *testing.T) {
	tests := []struct {
		purl string
		want bool
	}{
		{"pkg:npm/lodash", false},
		{"pkg:npm/lodash@4.17.21", false},
		{"pkg:npm/%40mycompany/utils?repository_url=https://npm.mycompany.com", true},
		{"pkg:npm/%40mycompany/utils@1.0.0?repository_url=https://npm.mycompany.com", true},
		{"pkg:pypi/requests?repository_url=https://pypi.internal.com/simple", true},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			got := hasRepositoryURL(tt.purl)
			if got != tt.want {
				t.Errorf("hasRepositoryURL(%q) = %v, want %v", tt.purl, got, tt.want)
			}
		})
	}
}

func TestFindLatestVersion(t *testing.T) {
	tests := []struct {
		versions []VersionInfo
		want     string
	}{
		{nil, ""},
		{[]VersionInfo{{Number: "1.0.0"}}, "1.0.0"},
		{[]VersionInfo{{Number: "1.0.0"}, {Number: "2.0.0"}, {Number: "1.5.0"}}, "2.0.0"},
		{[]VersionInfo{{Number: "3.0.0"}, {Number: "1.0.0"}}, "3.0.0"},
	}

	for _, tt := range tests {
		got := findLatestVersion(tt.versions)
		if got != tt.want {
			t.Errorf("findLatestVersion() = %q, want %q", got, tt.want)
		}
	}
}

func TestNewEcosystemsClient(t *testing.T) {
	client, err := NewEcosystemsClient()
	if err != nil {
		t.Fatalf("NewEcosystemsClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("NewEcosystemsClient() returned nil")
	}
	if client.client == nil {
		t.Error("client.client is nil")
	}
}

func TestNewRegistriesClient(t *testing.T) {
	client := NewRegistriesClient()
	if client == nil {
		t.Fatal("NewRegistriesClient() returned nil")
	}
	if client.client == nil {
		t.Error("client.client is nil")
	}
}

func TestNewDepsDevClient(t *testing.T) {
	client := NewDepsDevClient()
	if client == nil {
		t.Fatal("NewDepsDevClient() returned nil")
	}
	if client.baseURL == "" {
		t.Error("baseURL is empty")
	}
}

func TestDepsDevGetVersions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := depsdevPackageResponse{
			Versions: []depsdevVersion{
				{
					VersionKey: struct {
						System  string `json:"system"`
						Name    string `json:"name"`
						Version string `json:"version"`
					}{System: "NPM", Name: "lodash", Version: "4.17.20"},
					PublishedAt: "2020-08-13T00:00:00Z",
				},
				{
					VersionKey: struct {
						System  string `json:"system"`
						Name    string `json:"name"`
						Version string `json:"version"`
					}{System: "NPM", Name: "lodash", Version: "4.17.21"},
					PublishedAt: "2021-02-20T00:00:00Z",
					IsDefault:   true,
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &DepsDevClient{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	versions, err := client.GetVersions(context.Background(), "pkg:npm/lodash")
	if err != nil {
		t.Fatalf("GetVersions() error: %v", err)
	}

	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
	if versions[0].Number != "4.17.20" {
		t.Errorf("versions[0].Number = %q, want %q", versions[0].Number, "4.17.20")
	}
	if versions[1].Number != "4.17.21" {
		t.Errorf("versions[1].Number = %q, want %q", versions[1].Number, "4.17.21")
	}
}

func TestDepsDevGetVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := depsdevVersionResponse{
			VersionKey: struct {
				System  string `json:"system"`
				Name    string `json:"name"`
				Version string `json:"version"`
			}{System: "NPM", Name: "lodash", Version: "4.17.21"},
			PublishedAt: "2021-02-20T00:00:00Z",
			Licenses:    []string{"MIT"},
			Links: []struct {
				Label string `json:"label"`
				URL   string `json:"url"`
			}{
				{Label: "HOMEPAGE", URL: "https://lodash.com"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &DepsDevClient{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	v, err := client.GetVersion(context.Background(), "pkg:npm/lodash@4.17.21")
	if err != nil {
		t.Fatalf("GetVersion() error: %v", err)
	}

	if v.Number != "4.17.21" {
		t.Errorf("Number = %q, want %q", v.Number, "4.17.21")
	}
	if v.License != "MIT" {
		t.Errorf("License = %q, want %q", v.License, "MIT")
	}
}

func TestDepsDevBulkLookup(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// Package response
			resp := depsdevPackageResponse{
				Versions: []depsdevVersion{
					{
						VersionKey: struct {
							System  string `json:"system"`
							Name    string `json:"name"`
							Version string `json:"version"`
						}{System: "NPM", Name: "lodash", Version: "4.17.21"},
						PublishedAt: "2021-02-20T00:00:00Z",
						IsDefault:   true,
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
		} else {
			// Version response
			resp := depsdevVersionResponse{
				VersionKey: struct {
					System  string `json:"system"`
					Name    string `json:"name"`
					Version string `json:"version"`
				}{System: "NPM", Name: "lodash", Version: "4.17.21"},
				Licenses: []string{"MIT"},
				Links: []struct {
					Label string `json:"label"`
					URL   string `json:"url"`
				}{
					{Label: "HOMEPAGE", URL: "https://lodash.com"},
					{Label: "SOURCE_REPO", URL: "https://github.com/lodash/lodash"},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer srv.Close()

	client := &DepsDevClient{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	result, err := client.BulkLookup(context.Background(), []string{"pkg:npm/lodash"})
	if err != nil {
		t.Fatalf("BulkLookup() error: %v", err)
	}

	info, ok := result["pkg:npm/lodash"]
	if !ok {
		t.Fatal("expected pkg:npm/lodash in result")
	}
	if info.LatestVersion != "4.17.21" {
		t.Errorf("LatestVersion = %q, want %q", info.LatestVersion, "4.17.21")
	}
	if info.License != "MIT" {
		t.Errorf("License = %q, want %q", info.License, "MIT")
	}
	if info.Homepage != "https://lodash.com" {
		t.Errorf("Homepage = %q, want %q", info.Homepage, "https://lodash.com")
	}
	if info.Repository != "https://github.com/lodash/lodash" {
		t.Errorf("Repository = %q, want %q", info.Repository, "https://github.com/lodash/lodash")
	}
	if info.Source != "depsdev" {
		t.Errorf("Source = %q, want %q", info.Source, "depsdev")
	}
}
