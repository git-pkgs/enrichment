package enrichment

import (
	"context"
	"errors"
	"testing"
	"time"
)

// barrierBackend proves it ran concurrently with a counterpart barrierBackend:
// it signals its own start, then blocks until the counterpart also starts (or
// a generous timeout fires). If HybridClient.BulkLookup called backends
// sequentially, the first backend would return before the second ever
// started, and this wait would time out.
type barrierBackend struct {
	started chan struct{}
	peer    <-chan struct{}
	result  map[string]*PackageInfo
	err     error
}

func (b *barrierBackend) BulkLookup(_ context.Context, _ []string) (map[string]*PackageInfo, error) {
	close(b.started)
	select {
	case <-b.peer:
	case <-time.After(2 * time.Second):
		return nil, errors.New("peer backend never started: calls were not concurrent")
	}
	return b.result, b.err
}

func (b *barrierBackend) GetVersions(context.Context, string) ([]VersionInfo, error) {
	return nil, nil
}

func (b *barrierBackend) GetVersion(context.Context, string) (*VersionInfo, error) {
	return nil, nil
}

func newBarrierPair(ecoResult, regResult map[string]*PackageInfo, ecoErr, regErr error) (eco, reg *barrierBackend) {
	ecoStarted := make(chan struct{})
	regStarted := make(chan struct{})
	eco = &barrierBackend{started: ecoStarted, peer: regStarted, result: ecoResult, err: ecoErr}
	reg = &barrierBackend{started: regStarted, peer: ecoStarted, result: regResult, err: regErr}
	return eco, reg
}

func TestHybridClientBulkLookupRunsMixedBatchesConcurrentlyAndMerges(t *testing.T) {
	ecoInfo := &PackageInfo{Name: "lodash", Source: "ecosystems"}
	regInfo := &PackageInfo{Name: "left-pad", Source: "registries"}

	eco, reg := newBarrierPair(
		map[string]*PackageInfo{"pkg:npm/lodash": ecoInfo},
		map[string]*PackageInfo{"pkg:npm/left-pad?repository_url=https://example.com": regInfo},
		nil, nil,
	)
	c := &HybridClient{ecosystems: eco, registries: reg}

	result, err := c.BulkLookup(context.Background(), []string{
		"pkg:npm/lodash",
		"pkg:npm/left-pad?repository_url=https://example.com",
	})
	if err != nil {
		t.Fatalf("BulkLookup() error = %v, want nil (backends may not have run concurrently)", err)
	}

	if len(result) != 2 {
		t.Fatalf("BulkLookup() returned %d results, want 2: %+v", len(result), result)
	}
	if result["pkg:npm/lodash"] != ecoInfo {
		t.Errorf("ecosystems result not merged: got %+v", result["pkg:npm/lodash"])
	}
	if result["pkg:npm/left-pad?repository_url=https://example.com"] != regInfo {
		t.Errorf("registries result not merged: got %+v", result["pkg:npm/left-pad?repository_url=https://example.com"])
	}
}

func TestHybridClientBulkLookupReturnsEcosystemsErrorDeterministically(t *testing.T) {
	errEco := errors.New("ecosystems backend failed")
	errReg := errors.New("registries backend failed")

	// registries has no peer wait needed here since we only care about which
	// error wins; use plain fakes so neither blocks on the other.
	eco := &barrierBackend{started: make(chan struct{}), peer: closedChan(), err: errEco}
	reg := &barrierBackend{started: make(chan struct{}), peer: closedChan(), err: errReg}
	c := &HybridClient{ecosystems: eco, registries: reg}

	_, err := c.BulkLookup(context.Background(), []string{
		"pkg:npm/lodash",
		"pkg:npm/left-pad?repository_url=https://example.com",
	})
	if !errors.Is(err, errEco) {
		t.Fatalf("BulkLookup() error = %v, want ecosystems error %v regardless of goroutine finish order", err, errEco)
	}
}

func closedChan() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
