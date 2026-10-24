package enrichment

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/git-pkgs/registries"
	registryclient "github.com/git-pkgs/registries/client"
)

func TestRegistriesClientBlocksLoopbackRepositoryURL(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewRegistriesClient()
	purl := "pkg:npm/lodash?repository_url=" + url.QueryEscape(srv.URL)

	_, err := c.GetVersions(context.Background(), purl)
	if err == nil {
		t.Fatalf("expected safehttp to refuse loopback %s, got nil error", srv.URL)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("loopback server received %d requests; safehttp gate did not block dial", n)
	}
}

func TestRegistriesClientBulkLookupUsesSharedLatestPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "_id": "example",
  "versions": {
    "2.0.0": {"deprecated": "use the stable line"},
    "1.5.0": {},
    "1.0.0": {}
  },
  "time": {
    "1.5.0": "2025-01-01T00:00:00Z",
    "1.0.0": "2026-01-01T00:00:00Z"
  }
}`))
	}))
	defer srv.Close()

	httpClient := registries.NewClient(registryclient.WithHTTPClient(srv.Client()))
	c := &RegistriesClient{client: httpClient}
	purl := "pkg:npm/example?repository_url=" + url.QueryEscape(srv.URL)

	result, err := c.BulkLookup(context.Background(), []string{purl})
	if err != nil {
		t.Fatalf("BulkLookup: %v", err)
	}
	if result[purl] == nil || result[purl].LatestVersion != "1.0.0" {
		t.Fatalf("BulkLookup() = %+v, want latest version 1.0.0", result[purl])
	}
}

func TestRegistriesClientGetPackage(t *testing.T) {
	var requests atomic.Int32
	var countExample atomic.Bool
	countExample.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example":
			if countExample.Load() {
				requests.Add(1)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
  "_id": "example",
  "versions": {"1.5.0": {}, "1.0.0": {}},
  "time": {"1.5.0": "2025-01-01T00:00:00Z", "1.0.0": "2026-01-01T00:00:00Z"}
}`))
		case "/broken":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	httpClient := registries.NewClient(registryclient.WithHTTPClient(srv.Client()), registryclient.WithMaxRetries(0))
	c := &RegistriesClient{client: httpClient}
	repo := "?repository_url=" + url.QueryEscape(srv.URL)

	example := "pkg:npm/example" + repo
	info, err := c.GetPackage(context.Background(), example)
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}
	countExample.Store(false)
	bulk, err := c.BulkLookup(context.Background(), []string{example})
	if err != nil {
		t.Fatalf("BulkLookup: %v", err)
	}
	if info == nil || info.Name != "example" || info.LatestVersion != "1.0.0" || info.Source != "registries" {
		t.Fatalf("GetPackage() = %+v, want example at latest 1.0.0", info)
	}
	if !reflect.DeepEqual(info, bulk[example]) {
		t.Errorf("GetPackage() = %+v, BulkLookup() = %+v; want the same", info, bulk[example])
	}

	for name, wantNotFound := range map[string]bool{"missing": true, "broken": false} {
		info, err := c.GetPackage(context.Background(), "pkg:npm/"+name+repo)
		if err == nil {
			t.Errorf("GetPackage(%s) = %+v, nil; want an error", name, info)
			continue
		}
		if got := errors.Is(err, registries.ErrNotFound); got != wantNotFound {
			t.Errorf("GetPackage(%s) error %v: errors.Is(ErrNotFound) = %v, want %v", name, err, got, wantNotFound)
		}
	}

	if got := requests.Load(); got != 2 {
		t.Errorf("registry requests for example = %d, want 2 (package and versions)", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if info, err := c.GetPackage(ctx, example); !errors.Is(err, context.Canceled) {
		t.Errorf("GetPackage(canceled) = %+v, %v; want context.Canceled", info, err)
	}
}

func TestVersionInfoFromRegistryIncludesStatusAndMetadata(t *testing.T) {
	publishedAt := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC)
	got := versionInfoFromRegistry(registries.Version{
		Number:      "1.2.3",
		PublishedAt: publishedAt,
		Integrity:   "sha256-example",
		Licenses:    "MIT",
		Status:      registries.StatusRetracted,
		Metadata:    map[string]any{"reason": "security issue"},
	})

	if got.Number != "1.2.3" || got.PublishedAt != publishedAt || got.Integrity != "sha256-example" || got.License != "MIT" {
		t.Fatalf("version metadata = %+v", got)
	}
	if got.Status != string(registries.StatusRetracted) || got.Yanked {
		t.Fatalf("status metadata = %+v, want retracted", got)
	}
	if got.Metadata["reason"] != "security issue" {
		t.Fatalf("Metadata = %#v, want reason", got.Metadata)
	}

	yanked := versionInfoFromRegistry(registries.Version{Status: registries.StatusYanked})
	if yanked.Status != string(registries.StatusYanked) || !yanked.Yanked {
		t.Fatalf("yanked status metadata = %+v", yanked)
	}
}

func TestRegistriesClientBulkLookupCopiesFundingAndMaintainers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/funded":
			_, _ = w.Write([]byte(`{
  "_id": "funded",
  "dist-tags": {"latest": "1.0.0"},
  "versions": {
    "1.0.0": {
      "funding": [
        "https://github.com/sponsors/funded",
        {"type": "opencollective", "url": "https://opencollective.com/funded"}
      ]
    }
  },
  "maintainers": [{"name": "alice", "email": "alice@example.com"}]
}`))
		case "/unfunded":
			_, _ = w.Write([]byte(`{
  "_id": "unfunded",
  "dist-tags": {"latest": "2.0.0"},
  "versions": {"2.0.0": {}}
}`))
		case "/api/v1/gems/rails.json":
			_, _ = w.Write([]byte(`{
  "name": "rails",
  "version": "7.1.0",
  "funding_uri": "https://github.com/sponsors/rails"
}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	httpClient := registries.NewClient(registryclient.WithHTTPClient(srv.Client()))
	c := &RegistriesClient{client: httpClient}
	repo := "?repository_url=" + url.QueryEscape(srv.URL)
	funded := "pkg:npm/funded" + repo
	unfunded := "pkg:npm/unfunded" + repo
	gem := "pkg:gem/rails" + repo

	result, err := c.BulkLookup(context.Background(), []string{funded, unfunded, gem})
	if err != nil {
		t.Fatalf("BulkLookup: %v", err)
	}

	tests := []struct {
		purl            string
		wantFunding     []string
		wantMaintainers []Maintainer
	}{
		{
			purl:            funded,
			wantFunding:     []string{"https://github.com/sponsors/funded", "https://opencollective.com/funded"},
			wantMaintainers: []Maintainer{{Login: "alice", Email: "alice@example.com"}},
		},
		{purl: unfunded},
		{purl: gem, wantFunding: []string{"https://github.com/sponsors/rails"}},
	}
	for _, tt := range tests {
		info := result[tt.purl]
		if info == nil {
			t.Fatalf("BulkLookup() missing result for %s", tt.purl)
		}
		if !reflect.DeepEqual(info.FundingLinks, tt.wantFunding) {
			t.Errorf("%s FundingLinks = %#v, want %#v", tt.purl, info.FundingLinks, tt.wantFunding)
		}
		if !reflect.DeepEqual(info.Maintainers, tt.wantMaintainers) {
			t.Errorf("%s Maintainers = %#v, want %#v", tt.purl, info.Maintainers, tt.wantMaintainers)
		}
	}
}

func TestMaintainersFromRegistry(t *testing.T) {
	if got := maintainersFromRegistry(nil); got != nil {
		t.Errorf("maintainersFromRegistry(nil) = %#v, want nil", got)
	}
	if got := maintainersFromRegistry([]registries.Maintainer{}); got != nil {
		t.Errorf("maintainersFromRegistry(empty) = %#v, want nil", got)
	}

	got := maintainersFromRegistry([]registries.Maintainer{{
		UUID:  "123",
		Login: "alice",
		Name:  "Alice",
		Email: "alice@example.com",
		URL:   "https://example.com/alice",
		Role:  "owner",
	}})
	want := []Maintainer{{
		Login: "alice",
		Name:  "Alice",
		Email: "alice@example.com",
		URL:   "https://example.com/alice",
		Role:  "owner",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("maintainersFromRegistry() = %#v, want %#v", got, want)
	}
}
