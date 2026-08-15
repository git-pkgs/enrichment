package enrichment

import (
	"os"
	"os/exec"
	"strings"
	"sync"
)

const defaultUserAgent = "enrichment"

// Option configures an enrichment client.
type Option func(*options)

type options struct {
	userAgent string
	from      string
	apiKey    string
	batchSize int
}

// WithUserAgent sets the User-Agent header for API requests.
func WithUserAgent(ua string) Option {
	return func(o *options) {
		o.userAgent = ua
	}
}

// WithFrom sets the From header (email address) for ecosyste.ms API
// requests. Identifying the client moves it out of the shared
// rate-limit pool, which reduces stream-level rejections.
// Ignored by the direct registries client.
func WithFrom(email string) Option {
	return func(o *options) {
		o.from = email
	}
}

// WithAPIKey sets the bearer token sent on ecosyste.ms API requests.
// Ignored by the direct registries client.
func WithAPIKey(key string) Option {
	return func(o *options) {
		o.apiKey = key
	}
}

// WithBatchSize sets the per-request batch size for ecosyste.ms bulk
// lookups. Values <= 0 or above the upstream maximum fall back to the
// upstream default. Ignored by the direct registries client.
func WithBatchSize(size int) Option {
	return func(o *options) {
		o.batchSize = size
	}
}

func buildOptions(opts []Option) options {
	o := options{userAgent: defaultUserAgent}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// NewClient creates an enrichment client based on configuration.
//
// By default, uses a hybrid approach:
//   - PURLs with repository_url qualifier -> direct registry query
//   - Other PURLs -> ecosyste.ms API
//
// To skip ecosyste.ms and query all registries directly:
//   - Set GIT_PKGS_DIRECT=1 environment variable, or
//   - Set git config: git config --global pkgs.direct true
func NewClient(opts ...Option) (Client, error) { //nolint:ireturn // returns different concrete types based on config
	o := buildOptions(opts)
	if directMode() {
		return newRegistriesClient(o.userAgent), nil
	}
	return newHybridClient(o)
}

var (
	directModeFallbackOnce   sync.Once
	directModeFallbackResult bool
)

// directMode checks if direct registry mode is enabled.
// Environment variable takes precedence over git config; it is re-read on
// every call so overrides remain dynamic. The git config fallback spawns a
// subprocess, so its result is cached for the life of the process.
func directMode() bool {
	if v := os.Getenv("GIT_PKGS_DIRECT"); v != "" {
		return v == "true" || v == "1" || v == "yes"
	}

	directModeFallbackOnce.Do(func() {
		out, err := exec.Command("git", "config", "--get", "pkgs.direct").Output()
		if err != nil {
			return
		}

		val := strings.TrimSpace(string(out))
		directModeFallbackResult = val == "true" || val == "1" || val == "yes"
	})
	return directModeFallbackResult
}
