package enrichment

import (
	"context"
	"errors"
	"testing"
	"time"
)

// backendWaitTimeout bounds how long a fakeBackend blocks on its
// precondition before giving up, so a broken implementation fails the test
// instead of hanging it.
const backendWaitTimeout = 2 * time.Second

// errBackendWaitTimeout signals that a fakeBackend's precondition never
// happened, meaning the two backend calls did not overlap or did not
// complete in the order the test required. It is distinct from a backend
// error so tests can tell the two apart.
var errBackendWaitTimeout = errors.New("fake backend timed out waiting on its precondition")

// fakeBackend is a scriptable hybridBackend used to exercise
// HybridClient.BulkLookup without real HTTP clients. The channels let a test
// pin both the start overlap and the completion order of the two backends.
type fakeBackend struct {
	// started, when non-nil, is closed as BulkLookup is entered.
	started chan struct{}
	// waitFor, when non-nil, blocks BulkLookup from returning until it is
	// closed.
	waitFor <-chan struct{}
	// done, when non-nil, is closed as BulkLookup returns.
	done chan struct{}

	result map[string]*PackageInfo
	err    error
}

func (b *fakeBackend) BulkLookup(_ context.Context, _ []string) (map[string]*PackageInfo, error) {
	if b.started != nil {
		close(b.started)
	}
	if b.done != nil {
		defer close(b.done)
	}

	if b.waitFor != nil {
		select {
		case <-b.waitFor:
		case <-time.After(backendWaitTimeout):
			return nil, errBackendWaitTimeout
		}
	}
	return b.result, b.err
}

func (b *fakeBackend) GetVersions(context.Context, string) ([]VersionInfo, error) {
	return nil, nil
}

func (b *fakeBackend) GetVersion(context.Context, string) (*VersionInfo, error) {
	return nil, nil
}

const (
	ecoPURL = "pkg:npm/lodash"
	regPURL = "pkg:npm/left-pad?repository_url=https://example.com"
)

func mixedPURLs() []string {
	return []string{ecoPURL, regPURL}
}

// TestHybridClientBulkLookupRunsMixedBatchesConcurrentlyAndMerges proves the
// two backend calls overlap in time: each blocks until the other has started,
// which only resolves if they run concurrently. It also asserts both result
// sets land in the merged map.
func TestHybridClientBulkLookupRunsMixedBatchesConcurrentlyAndMerges(t *testing.T) {
	ecoInfo := &PackageInfo{Name: "lodash", Source: "ecosystems"}
	regInfo := &PackageInfo{Name: "left-pad", Source: "registries"}

	ecoStarted := make(chan struct{})
	regStarted := make(chan struct{})

	eco := &fakeBackend{
		started: ecoStarted,
		waitFor: regStarted,
		result:  map[string]*PackageInfo{ecoPURL: ecoInfo},
	}
	reg := &fakeBackend{
		started: regStarted,
		waitFor: ecoStarted,
		result:  map[string]*PackageInfo{regPURL: regInfo},
	}
	c := &HybridClient{ecosystems: eco, registries: reg}

	result, err := c.BulkLookup(context.Background(), mixedPURLs())
	if errors.Is(err, errBackendWaitTimeout) {
		t.Fatal("BulkLookup() ran the backends sequentially: neither call overlapped the other")
	}
	if err != nil {
		t.Fatalf("BulkLookup() error = %v, want nil", err)
	}

	if len(result) != 2 {
		t.Fatalf("BulkLookup() returned %d results, want 2: %+v", len(result), result)
	}
	if result[ecoPURL] != ecoInfo {
		t.Errorf("ecosystems result not merged: got %+v", result[ecoPURL])
	}
	if result[regPURL] != regInfo {
		t.Errorf("registries result not merged: got %+v", result[regPURL])
	}
}

// TestHybridClientBulkLookupPrefersEcosystemsErrorWhenRegistriesFinishesFirst
// pins the completion order so registries is guaranteed to return before
// ecosystems does. Error priority is positional, so the ecosystems error must
// still win. An implementation that surfaced whichever error arrived first
// would return the registries error here and fail.
func TestHybridClientBulkLookupPrefersEcosystemsErrorWhenRegistriesFinishesFirst(t *testing.T) {
	errEco := errors.New("ecosystems backend failed")
	errReg := errors.New("registries backend failed")

	regDone := make(chan struct{})

	// registries returns immediately and closes regDone on the way out.
	reg := &fakeBackend{done: regDone, err: errReg}
	// ecosystems cannot return until registries has already returned.
	eco := &fakeBackend{waitFor: regDone, err: errEco}
	c := &HybridClient{ecosystems: eco, registries: reg}

	_, err := c.BulkLookup(context.Background(), mixedPURLs())
	if errors.Is(err, errBackendWaitTimeout) {
		t.Fatal("registries never completed while ecosystems was in flight: the backends did not run concurrently")
	}
	if !errors.Is(err, errEco) {
		t.Fatalf("BulkLookup() error = %v, want ecosystems error %v even though registries completed first", err, errEco)
	}
}

// TestHybridClientBulkLookupReturnsRegistriesErrorWhenEcosystemsSucceeds
// covers the other branch: with no ecosystems error to take priority, the
// registries error must surface rather than being dropped.
func TestHybridClientBulkLookupReturnsRegistriesErrorWhenEcosystemsSucceeds(t *testing.T) {
	errReg := errors.New("registries backend failed")

	eco := &fakeBackend{result: map[string]*PackageInfo{ecoPURL: {Name: "lodash"}}}
	reg := &fakeBackend{err: errReg}
	c := &HybridClient{ecosystems: eco, registries: reg}

	if _, err := c.BulkLookup(context.Background(), mixedPURLs()); !errors.Is(err, errReg) {
		t.Fatalf("BulkLookup() error = %v, want registries error %v", err, errReg)
	}
}
