package enrichment

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ecosyste-ms/ecosystems-go"
	"github.com/ecosyste-ms/ecosystems-go/packages"
	"github.com/git-pkgs/registries"
	"github.com/oapi-codegen/nullable"
)

const testVersionLodash = "4.17.21"

func TestExtractRegistryURL(t *testing.T) {
	tests := []struct {
		purl       string
		ecosystem  string
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

func TestExtractChangelogFilename(t *testing.T) {
	t.Run("valid nested metadata", func(t *testing.T) {
		meta := map[string]interface{}{
			"metadata": map[string]interface{}{
				"files": map[string]interface{}{
					"changelog": "CHANGELOG.md",
				},
			},
		}
		got := extractChangelogFilename(meta)
		if got != "CHANGELOG.md" {
			t.Errorf("got %q, want %q", got, "CHANGELOG.md")
		}
	})

	t.Run("nil repo metadata", func(t *testing.T) {
		got := extractChangelogFilename(nil)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("missing metadata key", func(t *testing.T) {
		meta := map[string]interface{}{"other": "value"}
		got := extractChangelogFilename(meta)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("missing files key", func(t *testing.T) {
		meta := map[string]interface{}{
			"metadata": map[string]interface{}{"other": "value"},
		}
		got := extractChangelogFilename(meta)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("wrong type for metadata", func(t *testing.T) {
		meta := map[string]interface{}{"metadata": "not a map"}
		got := extractChangelogFilename(meta)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("wrong type for changelog", func(t *testing.T) {
		meta := map[string]interface{}{
			"metadata": map[string]interface{}{
				"files": map[string]interface{}{
					"changelog": 42,
				},
			},
		}
		got := extractChangelogFilename(meta)
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

func TestAdvisoryMapping(t *testing.T) {
	title := "Test advisory"
	severity := "high"
	cvss := float32(7.5)
	url := "https://example.com/advisory"

	a := Advisory{
		Title:       title,
		Severity:    severity,
		CVSSScore:   cvss,
		URL:         url,
		Identifiers: []string{"CVE-2024-1234", "GHSA-xxxx"},
	}

	if a.Title != title {
		t.Errorf("Title = %q, want %q", a.Title, title)
	}
	if a.Severity != severity {
		t.Errorf("Severity = %q, want %q", a.Severity, severity)
	}
	if a.CVSSScore != cvss {
		t.Errorf("CVSSScore = %v, want %v", a.CVSSScore, cvss)
	}
	if a.URL != url {
		t.Errorf("URL = %q, want %q", a.URL, url)
	}
	if len(a.Identifiers) != 2 || a.Identifiers[0] != "CVE-2024-1234" {
		t.Errorf("Identifiers = %v, want [CVE-2024-1234 GHSA-xxxx]", a.Identifiers)
	}
}

func TestConvertMaintainers(t *testing.T) {
	login := nullable.NewNullableWithValue("alice")
	name := nullable.NewNullableWithValue("Alice Example")
	email := nullable.NewNullableWithValue("alice@example.com")
	htmlURL := nullable.NewNullableWithValue("https://www.npmjs.com/~alice")
	role := nullable.NewNullableWithValue("owner")

	t.Run("populated", func(t *testing.T) {
		got := convertMaintainers([]packages.Maintainer{
			{Login: login, Name: name, Email: email, HTMLURL: htmlURL, Role: role},
			{Login: login},
		})
		want := []Maintainer{
			{Login: "alice", Name: "Alice Example", Email: "alice@example.com", URL: "https://www.npmjs.com/~alice", Role: "owner"},
			{Login: "alice"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("convertMaintainers() = %+v, want %+v", got, want)
		}
	})

	t.Run("nil fields", func(t *testing.T) {
		got := convertMaintainers([]packages.Maintainer{{}})
		if len(got) != 1 || got[0] != (Maintainer{}) {
			t.Errorf("convertMaintainers([{}]) = %+v, want [{}]", got)
		}
	})

	t.Run("empty", func(t *testing.T) {
		if got := convertMaintainers(nil); got != nil {
			t.Errorf("convertMaintainers(nil) = %v, want nil", got)
		}
		if got := convertMaintainers([]packages.Maintainer{}); got != nil {
			t.Errorf("convertMaintainers(empty) = %v, want nil", got)
		}
	})
}

func TestPackageInfoFundingAndMaintainers(t *testing.T) {
	info := &PackageInfo{
		FundingLinks: []string{"https://github.com/sponsors/alice", "https://opencollective.com/foo"},
		Maintainers: []Maintainer{
			{Login: "alice", Role: "owner"},
		},
	}

	if len(info.FundingLinks) != 2 {
		t.Errorf("len(FundingLinks) = %d, want 2", len(info.FundingLinks))
	}
	if info.FundingLinks[0] != "https://github.com/sponsors/alice" {
		t.Errorf("FundingLinks[0] = %q", info.FundingLinks[0])
	}
	if len(info.Maintainers) != 1 {
		t.Fatalf("len(Maintainers) = %d, want 1", len(info.Maintainers))
	}
	if info.Maintainers[0].Login != "alice" || info.Maintainers[0].Role != "owner" {
		t.Errorf("Maintainers[0] = %+v", info.Maintainers[0])
	}
}

func TestPackageInfoPopulationFields(t *testing.T) {
	info := &PackageInfo{
		Downloads:              1000000,
		DownloadsPeriod:        "last-month",
		DependentPackagesCount: 500,
		DependentReposCount:    2000,
		Advisories: []Advisory{
			{Title: "vuln", Severity: "critical", CVSSScore: 9.8, Identifiers: []string{"CVE-2024-0001"}},
		},
	}

	if info.Downloads != 1000000 {
		t.Errorf("Downloads = %d, want 1000000", info.Downloads)
	}
	if info.DownloadsPeriod != "last-month" {
		t.Errorf("DownloadsPeriod = %q, want %q", info.DownloadsPeriod, "last-month")
	}
	if info.DependentPackagesCount != 500 {
		t.Errorf("DependentPackagesCount = %d, want 500", info.DependentPackagesCount)
	}
	if info.DependentReposCount != 2000 {
		t.Errorf("DependentReposCount = %d, want 2000", info.DependentReposCount)
	}
	if len(info.Advisories) != 1 {
		t.Fatalf("len(Advisories) = %d, want 1", len(info.Advisories))
	}
	if info.Advisories[0].Severity != "critical" {
		t.Errorf("Advisories[0].Severity = %q, want %q", info.Advisories[0].Severity, "critical")
	}
}

func TestEcosystemsClientGetDependentsByRepositoryURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/packages/lookup":
			if got := r.URL.Query().Get("repository_url"); got != "https://github.com/acme/widget" {
				t.Errorf("repository_url = %q", got)
				http.Error(w, "bad repository_url", http.StatusInternalServerError)
				return
			}
			if got := r.URL.Query().Get("per_page"); got != "" {
				t.Errorf("per_page = %q, want empty for first lookup page", got)
				http.Error(w, "bad per_page", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`[
				{"name":"widget-extra","ecosystem":"npm","purl":"pkg:npm/widget-extra","registry":{"name":"npmjs.org"}},
				{"name":"widget","ecosystem":"npm","purl":"pkg:npm/widget","registry":{"name":"npmjs.org"}}
			]`))
		case "/registries/npmjs.org/packages/widget/dependent_packages":
			if got := r.URL.Query().Get("per_page"); got != "2" {
				t.Errorf("widget per_page = %q, want 2", got)
				http.Error(w, "bad per_page", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(`[
				{
					"name":"app-b",
					"ecosystem":"npm",
					"purl":"pkg:npm/app-b",
					"downloads":20,
					"dependent_repos_count":4,
					"registry_url":"https://npmjs.org/app-b",
					"latest_release_number":"2.0.0",
					"repo_metadata":{"html_url":"https://github.com/acme/app-b"}
				},
				{
					"name":"app-a",
					"ecosystem":"npm",
					"purl":"pkg:npm/app-a",
					"repository_url":"https://github.com/acme/app-a",
					"downloads":10,
					"dependent_repos_count":2,
					"latest_release_number":"1.0.0"
				}
			]`))
		case "/registries/npmjs.org/packages/widget-extra/dependent_packages":
			_, _ = w.Write([]byte(`[]`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	eco, err := ecosystems.NewClient("test-agent/1.0", ecosystems.WithPackagesServer(srv.URL))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client := &EcosystemsClient{client: eco}

	got, err := client.GetDependentsByRepositoryURL(context.Background(), "https://github.com/acme/widget", 5, 2)
	if err != nil {
		t.Fatalf("GetDependentsByRepositoryURL() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("groups = %+v, want 2", got)
	}
	if got[0].PackageName != "widget" || got[1].PackageName != "widget-extra" {
		t.Fatalf("groups not sorted by package name: %+v", got)
	}
	deps := got[0].Dependents
	if len(deps) != 2 {
		t.Fatalf("widget dependents = %+v, want 2", deps)
	}
	if deps[0].Name != "app-a" ||
		deps[0].Repository != "https://github.com/acme/app-a" ||
		deps[0].RegistryURL != "https://registry.npmjs.org" ||
		deps[0].LatestVersion != "1.0.0" ||
		deps[0].DependentReposCount != 2 {
		t.Fatalf("app-a = %+v", deps[0])
	}
	if deps[1].Name != "app-b" ||
		deps[1].Repository != "https://github.com/acme/app-b" ||
		deps[1].RegistryURL != "https://npmjs.org/app-b" ||
		deps[1].Downloads != 20 {
		t.Fatalf("app-b = %+v", deps[1])
	}
}

func TestEcosystemsClientGetDependentsByRepositoryURLErrorsWithoutRegistry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"name":"widget","ecosystem":"npm","purl":"pkg:npm/widget"}]`))
	}))
	defer srv.Close()

	eco, err := ecosystems.NewClient("test-agent/1.0", ecosystems.WithPackagesServer(srv.URL))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client := &EcosystemsClient{client: eco}
	_, err = client.GetDependentsByRepositoryURL(context.Background(), "https://github.com/acme/widget", 5, 2)
	if err == nil {
		t.Fatal("GetDependentsByRepositoryURL() error = nil, want missing registry error")
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
		name     string
		versions []VersionInfo
		scheme   string
		want     string
	}{
		{
			name: "empty",
		},
		{
			name:     "single version",
			versions: []VersionInfo{{Number: "1.0.0"}},
			scheme:   "npm",
			want:     "1.0.0",
		},
		{
			name: "highest semver",
			versions: []VersionInfo{
				{Number: "1.0.0"},
				{Number: "2.0.0"},
				{Number: "1.5.0"},
			},
			scheme: "npm",
			want:   "2.0.0",
		},
		{
			name: "keeps initial latest",
			versions: []VersionInfo{
				{Number: "3.0.0"},
				{Number: "1.0.0"},
			},
			scheme: "npm",
			want:   "3.0.0",
		},
		{
			name: "uses scheme ordering",
			versions: []VersionInfo{
				{Number: "1.0~rc1"},
				{Number: "1.0"},
			},
			scheme: "deb",
			want:   "1.0",
		},
		{
			name: "skips yanked status",
			versions: []VersionInfo{
				{Number: "2.0.0", Status: string(registries.StatusYanked)},
				{Number: "1.0.0"},
			},
			scheme: "npm",
			want:   "1.0.0",
		},
		{
			name: "skips deprecated status",
			versions: []VersionInfo{
				{Number: "2.0.0", Status: string(registries.StatusDeprecated)},
				{Number: "1.0.0"},
			},
			scheme: "npm",
			want:   "1.0.0",
		},
		{
			name: "skips retracted status",
			versions: []VersionInfo{
				{Number: "2.0.0", Status: string(registries.StatusRetracted)},
				{Number: "1.0.0"},
			},
			scheme: "npm",
			want:   "1.0.0",
		},
		{
			name: "skips yanked boolean",
			versions: []VersionInfo{
				{Number: "2.0.0", Yanked: true},
				{Number: "1.0.0"},
			},
			scheme: "npm",
			want:   "1.0.0",
		},
		{
			name: "returns empty when all unavailable",
			versions: []VersionInfo{
				{Number: "2.0.0", Status: string(registries.StatusYanked)},
				{Number: "1.0.0", Status: string(registries.StatusDeprecated)},
			},
			scheme: "npm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findLatestVersion(tt.versions, tt.scheme)
			if got != tt.want {
				t.Errorf("findLatestVersion() = %q, want %q", got, tt.want)
			}
		})
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

func TestEcosystemsClientGetVersionIncludesMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/registries/npmjs.org/packages/ua-parser-js/versions/1.0.41" {
			t.Errorf("path = %q, want version endpoint", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"number":"1.0.41",
			"licenses":"MIT",
			"status":"retracted",
			"metadata":{"reason":"security issue"}
		}`))
	}))
	defer srv.Close()

	ecosystemsClient, err := ecosystems.NewClient("test", ecosystems.WithPackagesServer(srv.URL))
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client := &EcosystemsClient{client: ecosystemsClient}

	version, err := client.GetVersion(context.Background(), "pkg:npm/ua-parser-js@1.0.41")
	if err != nil {
		t.Fatalf("GetVersion() error = %v", err)
	}
	if version == nil {
		t.Fatal("GetVersion() returned nil")
	}
	if version.License != "MIT" {
		t.Errorf("License = %q, want %q", version.License, "MIT")
	}
	if version.Status != "retracted" {
		t.Errorf("Status = %q, want %q", version.Status, "retracted")
	}
	if version.Yanked {
		t.Error("Yanked = true, want false for retracted version")
	}
	if version.Metadata["reason"] != "security issue" {
		t.Errorf("Metadata = %#v, want retraction reason", version.Metadata)
	}
}

func TestVersionInfoFromEcosystemsIncludesYankedStatus(t *testing.T) {
	status := nullable.NewNullableWithValue("yanked")
	integrity := nullable.NewNullableWithValue("sha256-example")
	license := nullable.NewNullableWithValue("MIT")
	metadata := nullable.NewNullableWithValue(map[string]any{"reason": "bad release"})

	got := versionInfoFromEcosystems("1.2.3", nil, integrity, license, status, metadata)

	if got.Number != "1.2.3" || got.Integrity != "sha256-example" || got.License != "MIT" {
		t.Fatalf("version metadata = %+v", got)
	}
	if got.Status != "yanked" || !got.Yanked {
		t.Fatalf("status metadata = %+v, want yanked", got)
	}
	if got.Metadata["reason"] != "bad release" {
		t.Fatalf("Metadata = %#v, want reason", got.Metadata)
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
					}{System: "NPM", Name: "lodash", Version: testVersionLodash},
					PublishedAt: "2021-02-20T00:00:00Z",
					IsDefault:   true,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
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
	if versions[1].Number != testVersionLodash {
		t.Errorf("versions[1].Number = %q, want %q", versions[1].Number, testVersionLodash)
	}
}

func TestDepsDevGetVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := depsdevVersionResponse{
			VersionKey: struct {
				System  string `json:"system"`
				Name    string `json:"name"`
				Version string `json:"version"`
			}{System: "NPM", Name: "lodash", Version: testVersionLodash},
			PublishedAt: "2021-02-20T00:00:00Z",
			Licenses:    []string{"MIT"},
			Links: []struct {
				Label string `json:"label"`
				URL   string `json:"url"`
			}{
				{Label: "HOMEPAGE", URL: "https://lodash.com"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
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

	if v.Number != testVersionLodash {
		t.Errorf("Number = %q, want %q", v.Number, testVersionLodash)
	}
	if v.License != "MIT" {
		t.Errorf("License = %q, want %q", v.License, "MIT")
	}
}

func TestDepsDevUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_ = json.NewEncoder(w).Encode(depsdevPackageResponse{})
	}))
	defer srv.Close()

	t.Run("default", func(t *testing.T) {
		client := NewDepsDevClient()
		client.baseURL = srv.URL
		client.httpClient = srv.Client()
		_, _ = client.GetVersions(context.Background(), "pkg:npm/lodash")
		if gotUA != "enrichment" {
			t.Errorf("default User-Agent = %q, want %q", gotUA, "enrichment")
		}
	})

	t.Run("custom", func(t *testing.T) {
		client := newDepsDevClient("git-pkgs/test")
		client.baseURL = srv.URL
		client.httpClient = srv.Client()
		_, _ = client.GetVersions(context.Background(), "pkg:npm/lodash")
		if gotUA != "git-pkgs/test" {
			t.Errorf("custom User-Agent = %q, want %q", gotUA, "git-pkgs/test")
		}
	})
}

func TestRegistriesClientUserAgent(t *testing.T) {
	client := newRegistriesClient("custom-agent")
	if client.client.UserAgent != "custom-agent" {
		t.Errorf("UserAgent = %q, want %q", client.client.UserAgent, "custom-agent")
	}
}

func TestNewClientWithUserAgent(t *testing.T) {
	t.Setenv("GIT_PKGS_DIRECT", "1")

	client, err := NewClient(WithUserAgent("test-ua"))
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	rc, ok := client.(*RegistriesClient)
	if !ok {
		t.Fatalf("expected *RegistriesClient, got %T", client)
	}
	if rc.client.UserAgent != "test-ua" {
		t.Errorf("UserAgent = %q, want %q", rc.client.UserAgent, "test-ua")
	}
}

func TestBuildOptions(t *testing.T) {
	o := buildOptions([]Option{
		WithUserAgent("ua"),
		WithFrom("dev@example.com"),
		WithAPIKey("secret"),
		WithBatchSize(25),
	})
	if o.userAgent != "ua" {
		t.Errorf("userAgent = %q, want %q", o.userAgent, "ua")
	}
	if o.from != "dev@example.com" {
		t.Errorf("from = %q, want %q", o.from, "dev@example.com")
	}
	if o.apiKey != "secret" {
		t.Errorf("apiKey = %q, want %q", o.apiKey, "secret")
	}
	if o.batchSize != 25 {
		t.Errorf("batchSize = %d, want %d", o.batchSize, 25)
	}
}

func TestBuildOptionsDefaults(t *testing.T) {
	o := buildOptions(nil)
	if o.userAgent != defaultUserAgent {
		t.Errorf("userAgent = %q, want %q", o.userAgent, defaultUserAgent)
	}
	if o.from != "" || o.apiKey != "" || o.batchSize != 0 {
		t.Errorf("expected zero values for from/apiKey/batchSize, got %+v", o)
	}
}

func TestNewEcosystemsClientWithAllOptions(t *testing.T) {
	c, err := newEcosystemsClient(options{
		userAgent: "git-pkgs/test",
		from:      "dev@example.com",
		apiKey:    "secret",
		batchSize: 25,
	})
	if err != nil {
		t.Fatalf("newEcosystemsClient: %v", err)
	}
	if c == nil || c.client == nil {
		t.Fatal("expected non-nil client")
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
						}{System: "NPM", Name: "lodash", Version: testVersionLodash},
						PublishedAt: "2021-02-20T00:00:00Z",
						IsDefault:   true,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		} else {
			// Version response
			resp := depsdevVersionResponse{
				VersionKey: struct {
					System  string `json:"system"`
					Name    string `json:"name"`
					Version string `json:"version"`
				}{System: "NPM", Name: "lodash", Version: testVersionLodash},
				Licenses: []string{"MIT"},
				Links: []struct {
					Label string `json:"label"`
					URL   string `json:"url"`
				}{
					{Label: "HOMEPAGE", URL: "https://lodash.com"},
					{Label: "SOURCE_REPO", URL: "https://github.com/lodash/lodash"},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
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
	if info.LatestVersion != testVersionLodash {
		t.Errorf("LatestVersion = %q, want %q", info.LatestVersion, testVersionLodash)
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

func TestDepsDevBulkLookupSkipsInvalidAndUnsupportedPURLs(t *testing.T) {
	client := &DepsDevClient{
		baseURL:    "http://127.0.0.1",
		httpClient: http.DefaultClient,
	}

	result, err := client.BulkLookup(context.Background(), []string{
		"not a purl",
		"pkg:unsupported/name",
	})
	if err != nil {
		t.Fatalf("BulkLookup() error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("BulkLookup() returned %d results, want 0", len(result))
	}
}

func TestDepsDevBulkLookupReturnsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := NewDepsDevClient()
	_, err := client.BulkLookup(ctx, []string{"pkg:npm/lodash"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("BulkLookup() error = %v, want context.Canceled", err)
	}
}

func TestDepsDevBulkLookupReturnsContextErrorForEmptyBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := NewDepsDevClient()
	_, err := client.BulkLookup(ctx, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("BulkLookup() error = %v, want context.Canceled", err)
	}
}

func TestDepsDevBulkLookupReturnsPackageError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "deps.dev unavailable", http.StatusBadGateway)
	}))
	defer srv.Close()

	client := &DepsDevClient{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := client.BulkLookup(context.Background(), []string{"pkg:npm/lodash"})
	if err == nil {
		t.Fatal("BulkLookup() error = nil, want error")
	}
}

func TestDepsDevBulkLookupSkipsPackageNotFound(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	client := &DepsDevClient{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	result, err := client.BulkLookup(context.Background(), []string{"pkg:npm/missing"})
	if err != nil {
		t.Fatalf("BulkLookup() error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("BulkLookup() returned %d results, want 0", len(result))
	}
}

func TestDepsDevGetVersionsReturnsNotFoundWithStatus(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	client := &DepsDevClient{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := client.GetVersions(context.Background(), "pkg:npm/missing")
	if !errors.Is(err, errDepsDevNotFound) {
		t.Fatalf("GetVersions() error = %v, want errDepsDevNotFound", err)
	}
	if !strings.Contains(err.Error(), "404 Not Found") {
		t.Fatalf("GetVersions() error = %q, want HTTP status", err)
	}
}

func TestDepsDevBulkLookupReturnsVersionError(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		if callCount == 1 {
			resp := depsdevPackageResponse{
				Versions: []depsdevVersion{
					{
						VersionKey: struct {
							System  string `json:"system"`
							Name    string `json:"name"`
							Version string `json:"version"`
						}{System: "NPM", Name: "lodash", Version: testVersionLodash},
						IsDefault: true,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.Error(w, "version unavailable", http.StatusBadGateway)
	}))
	defer srv.Close()

	client := &DepsDevClient{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := client.BulkLookup(context.Background(), []string{"pkg:npm/lodash"})
	if err == nil {
		t.Fatal("BulkLookup() error = nil, want error")
	}
}

func TestDepsDevBulkLookupSkipsVersionNotFound(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		if callCount == 1 {
			resp := depsdevPackageResponse{
				Versions: []depsdevVersion{
					{
						VersionKey: struct {
							System  string `json:"system"`
							Name    string `json:"name"`
							Version string `json:"version"`
						}{System: "NPM", Name: "missing-version", Version: testVersionLodash},
						IsDefault: true,
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	client := &DepsDevClient{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	result, err := client.BulkLookup(context.Background(), []string{"pkg:npm/missing-version"})
	if err != nil {
		t.Fatalf("BulkLookup() error: %v", err)
	}
	info, ok := result["pkg:npm/missing-version"]
	if !ok {
		t.Fatal("expected pkg:npm/missing-version in result")
	}
	if info.LatestVersion != testVersionLodash {
		t.Errorf("LatestVersion = %q, want %q", info.LatestVersion, testVersionLodash)
	}
	if info.License != "" {
		t.Errorf("License = %q, want empty", info.License)
	}
}

func TestDepsDevGetVersionReturnsNotFoundWithStatus(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	client := &DepsDevClient{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := client.GetVersion(context.Background(), "pkg:npm/missing@1.0.0")
	if !errors.Is(err, errDepsDevNotFound) {
		t.Fatalf("GetVersion() error = %v, want errDepsDevNotFound", err)
	}
	if !strings.Contains(err.Error(), "404 Not Found") {
		t.Fatalf("GetVersion() error = %q, want HTTP status", err)
	}
}
