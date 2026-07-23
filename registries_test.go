package enrichment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/git-pkgs/registries"
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

func TestAcquireSemaphore(t *testing.T) {
	sem := make(chan struct{}, 1)

	if !acquireSemaphore(context.Background(), sem) {
		t.Fatal("acquireSemaphore() = false, want true")
	}

	select {
	case <-sem:
	default:
		t.Fatal("semaphore was not acquired")
	}
}

func TestAcquireSemaphoreReturnsFalseWhenContextCanceled(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if acquireSemaphore(ctx, sem) {
		t.Fatal("acquireSemaphore() = true, want false")
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
