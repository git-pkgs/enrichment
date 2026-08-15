package enrichment

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// TestDirectModeFallbackCachesGitConfigResult proves the git config lookup
// runs exactly once per directModeFallback instance across repeated calls
// and that the cached result is reused.
func TestDirectModeFallbackCachesGitConfigResult(t *testing.T) {
	var calls int
	f := directModeFallback{
		lookup: func() ([]byte, error) {
			calls++
			return []byte("true\n"), nil
		},
	}

	for i := range 3 {
		if got := f.get(); !got {
			t.Fatalf("get() call %d = false, want true", i)
		}
	}

	if calls != 1 {
		t.Fatalf("lookup invoked %d times across 3 get() calls, want 1 (result should be cached)", calls)
	}
}

// TestDirectModeFallbackCachesFailure proves a failed git config lookup
// (git missing, or no such config key) is cached too rather than retried
// on every call.
func TestDirectModeFallbackCachesFailure(t *testing.T) {
	var calls int
	f := directModeFallback{
		lookup: func() ([]byte, error) {
			calls++
			return nil, errors.New("exit status 1")
		},
	}

	for i := range 3 {
		if got := f.get(); got {
			t.Fatalf("get() call %d = true, want false when the lookup fails", i)
		}
	}

	if calls != 1 {
		t.Fatalf("lookup invoked %d times across 3 get() calls, want 1 (failure should be cached)", calls)
	}
}

// TestDirectModeFallbackRunsLookupOnceUnderConcurrency proves concurrent
// callers collapse to a single lookup instead of racing to spawn several.
func TestDirectModeFallbackRunsLookupOnceUnderConcurrency(t *testing.T) {
	var calls atomic.Int32
	f := directModeFallback{
		lookup: func() ([]byte, error) {
			calls.Add(1)
			return []byte("1"), nil
		},
	}

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			if got := f.get(); !got {
				t.Error("get() = false, want true")
			}
		}()
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("lookup invoked %d times across %d concurrent get() calls, want 1", got, goroutines)
	}
}

// TestDirectModeFallbackParsesGitConfigValue covers the accepted truthy
// values and surrounding whitespace handling.
func TestDirectModeFallbackParsesGitConfigValue(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want bool
	}{
		{name: "true", out: "true\n", want: true},
		{name: "one", out: "1\n", want: true},
		{name: "yes", out: "yes\n", want: true},
		{name: "surrounding whitespace", out: "  true  \n", want: true},
		{name: "false", out: "false\n", want: false},
		{name: "zero", out: "0\n", want: false},
		{name: "empty", out: "\n", want: false},
		{name: "unrecognized", out: "maybe\n", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := directModeFallback{
				lookup: func() ([]byte, error) {
					return []byte(tt.out), nil
				},
			}
			if got := f.get(); got != tt.want {
				t.Fatalf("get() = %v for git config output %q, want %v", got, tt.out, tt.want)
			}
		})
	}
}
