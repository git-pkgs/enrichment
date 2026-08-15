package enrichment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDirectModeFallbackCachesGitConfigResult proves the git-config
// fallback subprocess runs exactly once per directModeFallback instance,
// even across repeated calls, and that the cached result is reused.
func TestDirectModeFallbackCachesGitConfigResult(t *testing.T) {
	dir := t.TempDir()
	countFile := filepath.Join(dir, "invocations")

	script := "#!/bin/sh\necho x >> " + countFile + "\necho true\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil { //nolint:gosec // test fixture, needs to be executable
		t.Fatalf("write fake git script: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	var f directModeFallback
	for i := range 3 {
		if got := f.get(); !got {
			t.Fatalf("get() call %d = false, want true (from fake git config)", i)
		}
	}

	data, err := os.ReadFile(countFile)
	if err != nil {
		t.Fatalf("read invocation count file: %v", err)
	}
	if got := strings.Count(string(data), "x"); got != 1 {
		t.Fatalf("fake git invoked %d times across 3 get() calls, want 1 (fallback should be cached)", got)
	}
}

// TestDirectModeFallbackCachesFailure proves a failed git-config lookup
// (e.g. git missing, or no such config key) is also cached rather than
// retried on every call.
func TestDirectModeFallbackCachesFailure(t *testing.T) {
	dir := t.TempDir()
	countFile := filepath.Join(dir, "invocations")

	script := "#!/bin/sh\necho x >> " + countFile + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o755); err != nil { //nolint:gosec // test fixture, needs to be executable
		t.Fatalf("write fake git script: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	var f directModeFallback
	for i := range 3 {
		if got := f.get(); got {
			t.Fatalf("get() call %d = true, want false when git config fails", i)
		}
	}

	data, err := os.ReadFile(countFile)
	if err != nil {
		t.Fatalf("read invocation count file: %v", err)
	}
	if got := strings.Count(string(data), "x"); got != 1 {
		t.Fatalf("fake git invoked %d times across 3 get() calls, want 1 (fallback should be cached even on failure)", got)
	}
}
