package scorecard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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

func TestGetScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/projects/github.com/lodash/lodash" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		resp := scorecardResponse{
			Score: 6.8,
			Date:  "2026-02-03T07:33:20Z",
			Checks: []struct {
				Name   string `json:"name"`
				Score  int    `json:"score"`
				Reason string `json:"reason"`
			}{
				{Name: "Binary-Artifacts", Score: 10, Reason: "no binaries found"},
				{Name: "Vulnerabilities", Score: 0, Reason: "79 existing vulnerabilities detected"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	result, err := client.GetScore(context.Background(), "github.com/lodash/lodash")
	if err != nil {
		t.Fatalf("GetScore() error: %v", err)
	}

	if result.Score != 6.8 {
		t.Errorf("Score = %f, want 6.8", result.Score)
	}
	if result.Date != "2026-02-03T07:33:20Z" {
		t.Errorf("Date = %q, want %q", result.Date, "2026-02-03T07:33:20Z")
	}
	if len(result.Checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(result.Checks))
	}
	if result.Checks[0].Name != "Binary-Artifacts" {
		t.Errorf("Checks[0].Name = %q, want %q", result.Checks[0].Name, "Binary-Artifacts")
	}
	if result.Checks[0].Score != 10 {
		t.Errorf("Checks[0].Score = %d, want 10", result.Checks[0].Score)
	}
}

func TestGetScoreStripsScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/projects/github.com/owner/repo" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		resp := scorecardResponse{Score: 5.0, Date: "2026-01-01"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	// Should strip https:// and .git
	result, err := client.GetScore(context.Background(), "https://github.com/owner/repo.git")
	if err != nil {
		t.Fatalf("GetScore() error: %v", err)
	}
	if result.Score != 5.0 {
		t.Errorf("Score = %f, want 5.0", result.Score)
	}
}

func TestDefaultUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_ = json.NewEncoder(w).Encode(scorecardResponse{Score: 5.0})
	}))
	defer srv.Close()

	client := New()
	client.baseURL = srv.URL
	client.httpClient = srv.Client()
	_, _ = client.GetScore(context.Background(), "github.com/test/repo")

	if gotUA != "enrichment" {
		t.Errorf("default User-Agent = %q, want %q", gotUA, "enrichment")
	}
}

func TestCustomUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_ = json.NewEncoder(w).Encode(scorecardResponse{Score: 5.0})
	}))
	defer srv.Close()

	client := New("git-pkgs/test")
	client.baseURL = srv.URL
	client.httpClient = srv.Client()
	_, _ = client.GetScore(context.Background(), "github.com/test/repo")

	if gotUA != "git-pkgs/test" {
		t.Errorf("User-Agent = %q, want %q", gotUA, "git-pkgs/test")
	}
}

func TestGetScoreNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := &Client{
		baseURL:    srv.URL,
		httpClient: srv.Client(),
	}

	_, err := client.GetScore(context.Background(), "github.com/nonexistent/repo")
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
}
