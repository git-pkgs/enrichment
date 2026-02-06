// Package scorecard provides a client for the OpenSSF Scorecard API.
// It returns repo-level security scores rather than package metadata.
package scorecard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Result contains the scorecard result for a repository.
type Result struct {
	Score  float64
	Date   string
	Checks []Check
}

// Check contains a single scorecard check result.
type Check struct {
	Name   string
	Score  int
	Reason string
}

// Client queries the OpenSSF Scorecard API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New creates a new scorecard client.
func New() *Client {
	return &Client{
		baseURL: "https://api.securityscorecards.dev",
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetScore fetches the scorecard for a repository.
// The repoURL should be in the form "github.com/owner/repo".
func (c *Client) GetScore(ctx context.Context, repoURL string) (*Result, error) {
	// Strip scheme if present
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "http://")
	repoURL = strings.TrimSuffix(repoURL, ".git")

	u := fmt.Sprintf("%s/projects/%s", c.baseURL, repoURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scorecard: %s", resp.Status)
	}

	var raw scorecardResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	result := &Result{
		Score: raw.Score,
		Date:  raw.Date,
	}
	for _, ch := range raw.Checks {
		result.Checks = append(result.Checks, Check{
			Name:   ch.Name,
			Score:  ch.Score,
			Reason: ch.Reason,
		})
	}
	return result, nil
}

type scorecardResponse struct {
	Score  float64 `json:"score"`
	Date   string  `json:"date"`
	Checks []struct {
		Name   string `json:"name"`
		Score  int    `json:"score"`
		Reason string `json:"reason"`
	} `json:"checks"`
}
