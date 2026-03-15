package endoflife

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	client := New()
	if client == nil {
		t.Fatal("New() returned nil")
	}
	if client.baseURL == "" {
		t.Error("baseURL is empty")
	}
}

func TestGetAllProducts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/all.json" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]string{"python", "nodejs", "ruby"})
	}))
	defer srv.Close()

	client := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	products, err := client.GetAllProducts(context.Background())
	if err != nil {
		t.Fatalf("GetAllProducts() error: %v", err)
	}

	if len(products) != 3 {
		t.Fatalf("expected 3 products, got %d", len(products))
	}
	if products[0] != "python" {
		t.Errorf("products[0] = %q, want %q", products[0], "python")
	}
}

func TestGetProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/nodejs.json" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		resp := []map[string]any{
			{
				"cycle":             "22",
				"releaseDate":       "2024-04-24",
				"eol":               "2027-04-30",
				"latest":            "22.22.1",
				"latestReleaseDate": "2026-03-05",
				"lts":               "2024-10-29",
				"support":           "2025-10-21",
				"extendedSupport":   true,
			},
			{
				"cycle":             "21",
				"releaseDate":       "2023-10-17",
				"eol":               "2024-06-01",
				"latest":            "21.7.3",
				"latestReleaseDate": "2024-04-10",
				"lts":               false,
				"support":           "2024-04-01",
				"extendedSupport":   false,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	cycles, err := client.GetProduct(context.Background(), "nodejs")
	if err != nil {
		t.Fatalf("GetProduct() error: %v", err)
	}

	if len(cycles) != 2 {
		t.Fatalf("expected 2 cycles, got %d", len(cycles))
	}

	c := cycles[0]
	if c.Name != "22" {
		t.Errorf("Name = %q, want %q", c.Name, "22")
	}
	if c.Latest != "22.22.1" {
		t.Errorf("Latest = %q, want %q", c.Latest, "22.22.1")
	}
	if c.ReleaseDate.Format("2006-01-02") != "2024-04-24" {
		t.Errorf("ReleaseDate = %q, want %q", c.ReleaseDate.Format("2006-01-02"), "2024-04-24")
	}
	if c.EOL.Date.Format("2006-01-02") != "2027-04-30" {
		t.Errorf("EOL date = %q, want %q", c.EOL.Date.Format("2006-01-02"), "2027-04-30")
	}
	if !c.IsLTS() {
		t.Error("expected cycle 22 to be LTS")
	}
	if c.IsEOL() {
		t.Error("expected cycle 22 to not be EOL yet")
	}

	c2 := cycles[1]
	if c2.IsLTS() {
		t.Error("expected cycle 21 to not be LTS")
	}
	if !c2.IsEOL() {
		t.Error("expected cycle 21 to be EOL")
	}
}

func TestGetCycle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/python/3.12.json" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		resp := map[string]any{
			"cycle":             "3.12",
			"releaseDate":       "2023-10-02",
			"eol":               "2028-10-02",
			"latest":            "3.12.9",
			"latestReleaseDate": "2025-02-04",
			"lts":               false,
			"support":           "2025-04-02",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	cycle, err := client.GetCycle(context.Background(), "python", "3.12")
	if err != nil {
		t.Fatalf("GetCycle() error: %v", err)
	}

	if cycle.Name != "3.12" {
		t.Errorf("Name = %q, want %q", cycle.Name, "3.12")
	}
	if cycle.Latest != "3.12.9" {
		t.Errorf("Latest = %q, want %q", cycle.Latest, "3.12.9")
	}
	if cycle.IsEOL() {
		t.Error("expected Python 3.12 to not be EOL")
	}
	if cycle.IsLTS() {
		t.Error("expected Python 3.12 to not be LTS")
	}
}

func TestGetProductNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := client.GetProduct(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestGetCycleNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := client.GetCycle(context.Background(), "python", "99.99")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestDateOrBoolUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantBool *bool
		wantDate string
	}{
		{
			name:     "boolean true",
			input:    `true`,
			wantBool: boolPtr(true),
		},
		{
			name:     "boolean false",
			input:    `false`,
			wantBool: boolPtr(false),
		},
		{
			name:     "date string",
			input:    `"2025-04-30"`,
			wantDate: "2025-04-30",
		},
		{
			name:  "empty string",
			input: `""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d DateOrBool
			if err := json.Unmarshal([]byte(tt.input), &d); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			if tt.wantBool != nil {
				if d.Bool == nil {
					t.Fatal("expected Bool to be set")
				}
				if *d.Bool != *tt.wantBool {
					t.Errorf("Bool = %v, want %v", *d.Bool, *tt.wantBool)
				}
			}

			if tt.wantDate != "" {
				if d.Date.Format("2006-01-02") != tt.wantDate {
					t.Errorf("Date = %q, want %q", d.Date.Format("2006-01-02"), tt.wantDate)
				}
			}
		})
	}
}

func TestIsEOLWithBooleanTrue(t *testing.T) {
	c := &Cycle{EOL: DateOrBool{Bool: boolPtr(true)}}
	if !c.IsEOL() {
		t.Error("expected IsEOL() = true when eol is boolean true")
	}
}

func TestIsEOLWithBooleanFalse(t *testing.T) {
	c := &Cycle{EOL: DateOrBool{Bool: boolPtr(false)}}
	if c.IsEOL() {
		t.Error("expected IsEOL() = false when eol is boolean false")
	}
}

func TestIsEOLWithFutureDate(t *testing.T) {
	future := time.Now().Add(365 * 24 * time.Hour)
	c := &Cycle{EOL: DateOrBool{Date: Date{Time: future}}}
	if c.IsEOL() {
		t.Error("expected IsEOL() = false for future date")
	}
}

func TestIsEOLWithPastDate(t *testing.T) {
	past := time.Now().Add(-365 * 24 * time.Hour)
	c := &Cycle{EOL: DateOrBool{Date: Date{Time: past}}}
	if !c.IsEOL() {
		t.Error("expected IsEOL() = true for past date")
	}
}

func TestIsSupportedWithFutureDate(t *testing.T) {
	future := time.Now().Add(365 * 24 * time.Hour)
	c := &Cycle{Support: DateOrBool{Date: Date{Time: future}}}
	if !c.IsSupported() {
		t.Error("expected IsSupported() = true for future support date")
	}
}

func TestIsSupportedWithPastDate(t *testing.T) {
	past := time.Now().Add(-365 * 24 * time.Hour)
	c := &Cycle{Support: DateOrBool{Date: Date{Time: past}}}
	if c.IsSupported() {
		t.Error("expected IsSupported() = false for past support date")
	}
}

func TestIsSupportedFallsBackToEOL(t *testing.T) {
	future := time.Now().Add(365 * 24 * time.Hour)
	c := &Cycle{EOL: DateOrBool{Date: Date{Time: future}}}
	if !c.IsSupported() {
		t.Error("expected IsSupported() = true when no support field but not EOL")
	}
}

func TestDefaultUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_ = json.NewEncoder(w).Encode([]string{})
	}))
	defer srv.Close()

	client := New()
	client.baseURL = srv.URL
	client.httpClient = srv.Client()
	_, _ = client.GetAllProducts(context.Background())

	if gotUA != "enrichment" {
		t.Errorf("default User-Agent = %q, want %q", gotUA, "enrichment")
	}
}

func TestCustomUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_ = json.NewEncoder(w).Encode([]string{})
	}))
	defer srv.Close()

	client := New("git-pkgs/test")
	client.baseURL = srv.URL
	client.httpClient = srv.Client()
	_, _ = client.GetAllProducts(context.Background())

	if gotUA != "git-pkgs/test" {
		t.Errorf("User-Agent = %q, want %q", gotUA, "git-pkgs/test")
	}
}

func TestDateOrBoolMarshal(t *testing.T) {
	tests := []struct {
		name string
		d    DateOrBool
		want string
	}{
		{
			name: "boolean true",
			d:    DateOrBool{Bool: boolPtr(true)},
			want: "true",
		},
		{
			name: "boolean false",
			d:    DateOrBool{Bool: boolPtr(false)},
			want: "false",
		},
		{
			name: "date",
			d:    DateOrBool{Date: Date{Time: time.Date(2025, 4, 30, 0, 0, 0, 0, time.UTC)}},
			want: `"2025-04-30"`,
		},
		{
			name: "nil",
			d:    DateOrBool{},
			want: "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.d)
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}
			if string(data) != tt.want {
				t.Errorf("Marshal = %s, want %s", data, tt.want)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}
