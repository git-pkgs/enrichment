package enrichment

import (
	"context"
	"errors"
	"testing"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/vulns"
)

type fakeVulnerabilitySource struct {
	queryResult      []vulns.Vulnerability
	queryBatchResult [][]vulns.Vulnerability
	err              error
	queries          []*purl.PURL
	batchCalls       int
}

func (s *fakeVulnerabilitySource) Name() string {
	return "fake"
}

func (s *fakeVulnerabilitySource) Query(_ context.Context, p *purl.PURL) ([]vulns.Vulnerability, error) {
	s.queries = append(s.queries, p)
	return s.queryResult, s.err
}

func (s *fakeVulnerabilitySource) QueryBatch(context.Context, []*purl.PURL) ([][]vulns.Vulnerability, error) {
	s.batchCalls++
	return s.queryBatchResult, s.err
}

func (s *fakeVulnerabilitySource) Get(context.Context, string) (*vulns.Vulnerability, error) {
	return nil, nil
}

func TestVulnerabilityClientCheck(t *testing.T) {
	source := &fakeVulnerabilitySource{
		queryResult: []vulns.Vulnerability{
			{
				ID:      "GHSA-test",
				Summary: "test summary",
				Details: "test details",
				Aliases: []string{"CVE-2024-0001"},
				Severity: []vulns.Severity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
				},
				References: []vulns.Reference{
					{Type: "ADVISORY", URL: "https://example.com/advisory"},
					{Type: "WEB", URL: ""},
				},
				Affected: []vulns.Affected{
					{
						Package: vulns.Package{Ecosystem: "npm", Name: "lodash"},
						Ranges: []vulns.Range{
							{Type: "SEMVER", Events: []vulns.Event{{Introduced: "0"}, {Fixed: "4.17.21"}}},
						},
					},
				},
			},
		},
	}

	client := NewVulnerabilityClient(WithVulnerabilitySource(source))
	got, err := client.Check(context.Background(), "npm", "lodash", "4.17.20")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(Check()) = %d, want 1", len(got))
	}

	info := got[0]
	if info.ID != "GHSA-test" {
		t.Errorf("ID = %q, want GHSA-test", info.ID)
	}
	if info.Severity != "high" {
		t.Errorf("Severity = %q, want high", info.Severity)
	}
	if info.CVSSScore != 7.5 {
		t.Errorf("CVSSScore = %v, want 7.5", info.CVSSScore)
	}
	if info.CVSSVersion != "3.1" {
		t.Errorf("CVSSVersion = %q, want 3.1", info.CVSSVersion)
	}
	if info.FixedVersion != "4.17.21" {
		t.Errorf("FixedVersion = %q, want 4.17.21", info.FixedVersion)
	}
	if len(info.References) != 1 || info.References[0] != "https://example.com/advisory" {
		t.Errorf("References = %v, want advisory URL only", info.References)
	}
	if len(info.Aliases) != 1 || info.Aliases[0] != "CVE-2024-0001" {
		t.Errorf("Aliases = %v, want CVE alias", info.Aliases)
	}
	if info.Source != "fake" {
		t.Errorf("Source = %q, want fake", info.Source)
	}
}

func TestVulnerabilityClientRejectsSwiftRegistryIdentities(t *testing.T) {
	for _, name := range []string{"apple.swift-nio", "apple/swift-nio", "Apple.Swift-NIO", "swift-nio"} {
		t.Run(name, func(t *testing.T) {
			source := &fakeVulnerabilitySource{}
			client := NewVulnerabilityClient(WithVulnerabilitySource(source))
			if _, err := client.Check(context.Background(), "Swift", name, "2.0.0"); !errors.Is(err, ErrUnsupportedVulnerabilityIdentity) {
				t.Errorf("Check error = %v, want unsupported identity", err)
			}
			if _, err := client.CheckBatch(context.Background(), []VulnerabilityQuery{
				{Ecosystem: "swift", Name: "github.com/apple/swift-nio", Version: "2.0.0"},
				{Ecosystem: "swift", Name: name, Version: "2.0.0"},
			}); !errors.Is(err, ErrUnsupportedVulnerabilityIdentity) {
				t.Errorf("CheckBatch error = %v, want unsupported identity", err)
			}
			if len(source.queries) != 0 || source.batchCalls != 0 {
				t.Fatalf("unsupported identity reached vulnerability source: queries=%v batchCalls=%d", source.queries, source.batchCalls)
			}
		})
	}
}

func TestVulnerabilityClientSwiftSourceCoordinate(t *testing.T) {
	source := &fakeVulnerabilitySource{}
	client := NewVulnerabilityClient(WithVulnerabilitySource(source))
	if _, err := client.Check(context.Background(), "Swift", "github.com/Apple/Swift-NIO", "2.0.0"); err != nil {
		t.Fatal(err)
	}
	if len(source.queries) != 1 || source.queries[0] == nil || source.queries[0].String() != "pkg:swift/github.com/Apple/Swift-NIO@2.0.0" {
		t.Fatalf("queried %v, want source PURL", source.queries)
	}
}

func TestVulnerabilityClientCheckUsesFixedVersionForQueriedRange(t *testing.T) {
	source := &fakeVulnerabilitySource{
		queryResult: []vulns.Vulnerability{
			{
				ID: "GHSA-multi-range",
				Affected: []vulns.Affected{
					{
						Package: vulns.Package{Ecosystem: "npm", Name: "example"},
						Ranges: []vulns.Range{
							{
								Type: "SEMVER",
								Events: []vulns.Event{
									{Introduced: "0"},
									{Fixed: "1.0.0"},
								},
							},
							{
								Type: "SEMVER",
								Events: []vulns.Event{
									{Introduced: "1.5.0"},
									{Fixed: "2.0.0"},
								},
							},
						},
					},
				},
			},
		},
	}

	client := NewVulnerabilityClient(WithVulnerabilitySource(source))
	got, err := client.Check(context.Background(), "npm", "example", "1.6.0")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(Check()) = %d, want 1", len(got))
	}
	if got[0].FixedVersion != "2.0.0" {
		t.Errorf("FixedVersion = %q, want 2.0.0", got[0].FixedVersion)
	}
}

func TestVulnerabilityClientCheckMatchesMappedEcosystemAffectedPackage(t *testing.T) {
	source := &fakeVulnerabilitySource{
		queryResult: []vulns.Vulnerability{
			{
				ID: "GHSA-mapped-ecosystem",
				Affected: []vulns.Affected{
					{
						Package: vulns.Package{Ecosystem: "Alpine", Name: "openssl"},
						Ranges: []vulns.Range{
							{
								Type: "ECOSYSTEM",
								Events: []vulns.Event{
									{Introduced: "0"},
									{Fixed: "3.0.8-r1"},
								},
							},
						},
					},
				},
			},
		},
	}

	client := NewVulnerabilityClient(WithVulnerabilitySource(source))
	got, err := client.Check(context.Background(), "alpine", "openssl", "3.0.8-r0")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(Check()) = %d, want 1", len(got))
	}
	if got[0].FixedVersion != "3.0.8-r1" {
		t.Errorf("FixedVersion = %q, want 3.0.8-r1", got[0].FixedVersion)
	}
}

func TestVulnerabilityPURLMappedEcosystems(t *testing.T) {
	tests := []struct {
		name          string
		ecosystem     string
		packageName   string
		version       string
		wantType      string
		wantNamespace string
		wantName      string
	}{
		{
			name:          "alpine default namespace",
			ecosystem:     "alpine",
			packageName:   "openssl",
			version:       "3.0.0",
			wantType:      "apk",
			wantNamespace: "alpine",
			wantName:      "openssl",
		},
		{
			name:          "arch default namespace",
			ecosystem:     "arch",
			packageName:   "pacman",
			version:       "6.0.2",
			wantType:      "alpm",
			wantNamespace: "arch",
			wantName:      "pacman",
		},
		{
			name:          "github actions subpath",
			ecosystem:     "github-actions",
			packageName:   "actions/checkout/action.yml",
			version:       "v4",
			wantType:      "githubactions",
			wantNamespace: "actions",
			wantName:      "checkout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vulnerabilityPURL(tt.ecosystem, tt.packageName, tt.version)
			if err != nil {
				t.Fatalf("vulnerabilityPURL() error: %v", err)
			}
			if got.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", got.Type, tt.wantType)
			}
			if got.Namespace != tt.wantNamespace {
				t.Errorf("Namespace = %q, want %q", got.Namespace, tt.wantNamespace)
			}
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.Version != tt.version {
				t.Errorf("Version = %q, want %q", got.Version, tt.version)
			}
		})
	}
}

func TestVulnerabilityClientCheckBatch(t *testing.T) {
	source := &fakeVulnerabilitySource{
		queryBatchResult: [][]vulns.Vulnerability{
			{{ID: "GHSA-one"}},
			nil,
		},
	}

	client := NewVulnerabilityClient(WithVulnerabilitySource(source))
	got, err := client.CheckBatch(context.Background(), []VulnerabilityQuery{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"},
		{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"},
	})
	if err != nil {
		t.Fatalf("CheckBatch() error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(CheckBatch()) = %d, want 2", len(got))
	}
	if got[0].Query.Name != "lodash" || len(got[0].Vulnerabilities) != 1 {
		t.Errorf("first result = %+v, want lodash with one vulnerability", got[0])
	}
	if got[1].Query.Name != "requests" || got[1].Vulnerabilities != nil {
		t.Errorf("second result = %+v, want requests with no vulnerabilities", got[1])
	}
}

func TestVulnerabilityClientErrors(t *testing.T) {
	t.Run("invalid query", func(t *testing.T) {
		client := NewVulnerabilityClient(WithVulnerabilitySource(&fakeVulnerabilitySource{}))
		_, err := client.Check(context.Background(), "npm", "", "1.0.0")
		if err == nil {
			t.Fatal("Check() error = nil, want error")
		}
		if err.Error() != "package name is required" {
			t.Fatalf("Check() error = %q, want package name is required", err)
		}
	})

	t.Run("unsupported ecosystem", func(t *testing.T) {
		client := NewVulnerabilityClient(WithVulnerabilitySource(&fakeVulnerabilitySource{}))
		_, err := client.Check(context.Background(), " unknown-ecosystem ", "pkg", "1.0.0")
		if err == nil {
			t.Fatal("Check() error = nil, want unsupported ecosystem error")
		}
		if err.Error() != `unsupported ecosystem: " unknown-ecosystem "` {
			t.Fatalf("Check() error = %q, want quoted unsupported ecosystem", err)
		}
	})

	t.Run("source error", func(t *testing.T) {
		wantErr := errors.New("source unavailable")
		client := NewVulnerabilityClient(WithVulnerabilitySource(&fakeVulnerabilitySource{err: wantErr}))
		if _, err := client.Check(context.Background(), "npm", "lodash", "4.17.20"); !errors.Is(err, wantErr) {
			t.Fatalf("Check() error = %v, want %v", err, wantErr)
		}
	})

	t.Run("batch result count mismatch", func(t *testing.T) {
		client := NewVulnerabilityClient(WithVulnerabilitySource(&fakeVulnerabilitySource{
			queryBatchResult: [][]vulns.Vulnerability{{{ID: "only-one"}}},
		}))
		_, err := client.CheckBatch(context.Background(), []VulnerabilityQuery{
			{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
			{Ecosystem: "npm", Name: "b", Version: "1.0.0"},
		})
		if err == nil {
			t.Fatal("CheckBatch() error = nil, want mismatch error")
		}
	})
}
