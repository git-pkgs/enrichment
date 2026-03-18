// Package endoflife provides a client for the endoflife.date API.
// It returns product lifecycle data including release dates, EOL dates,
// and support status for software products and runtimes.
package endoflife

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const defaultHTTPTimeout = 30 * time.Second

// Cycle contains lifecycle information for a single release cycle of a product.
type Cycle struct {
	Name              string    `json:"cycle"`
	ReleaseDate       Date      `json:"releaseDate"`
	EOL               DateOrBool `json:"eol"`
	Latest            string    `json:"latest"`
	LatestReleaseDate Date      `json:"latestReleaseDate"`
	LTS               DateOrBool `json:"lts"`
	Support           DateOrBool `json:"support"`
	ExtendedSupport   DateOrBool `json:"extendedSupport"`
}

// IsEOL reports whether this cycle has reached end of life.
func (c *Cycle) IsEOL() bool {
	if c.EOL.Bool != nil {
		return *c.EOL.Bool
	}
	if c.EOL.Date.IsZero() {
		return false
	}
	return time.Now().After(c.EOL.Date.Time)
}

// IsSupported reports whether this cycle still receives active support
// (bug fixes, not just security patches).
func (c *Cycle) IsSupported() bool {
	if c.Support.Bool != nil {
		return *c.Support.Bool
	}
	if c.Support.Date.IsZero() {
		return !c.IsEOL()
	}
	return time.Now().Before(c.Support.Date.Time)
}

// IsLTS reports whether this cycle is a long-term support release.
func (c *Cycle) IsLTS() bool {
	if c.LTS.Bool != nil {
		return *c.LTS.Bool
	}
	// If LTS has a date, it's an LTS release (the date is when LTS started).
	return !c.LTS.Date.IsZero()
}

// Date is a date parsed from the "YYYY-MM-DD" format used by the API.
type Date struct {
	time.Time
}

func (d *Date) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return nil // not a string, leave zero
	}
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return err
	}
	d.Time = t
	return nil
}

func (d Date) MarshalJSON() ([]byte, error) {
	if d.IsZero() {
		return json.Marshal("")
	}
	return json.Marshal(d.Format("2006-01-02"))
}

// DateOrBool represents a field that can be either a date string ("2025-04-30")
// or a boolean (true/false). The endoflife.date API uses this for eol, lts,
// support, and extendedSupport fields.
type DateOrBool struct {
	Date Date
	Bool *bool
}

func (d *DateOrBool) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		d.Bool = &b
		return nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "" {
			return nil
		}
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return err
		}
		d.Date = Date{Time: t}
		return nil
	}

	return nil
}

func (d DateOrBool) MarshalJSON() ([]byte, error) {
	if d.Bool != nil {
		return json.Marshal(*d.Bool)
	}
	if d.Date.IsZero() {
		return json.Marshal(nil)
	}
	return json.Marshal(d.Date.Format("2006-01-02"))
}

// Client queries the endoflife.date API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

// New creates a new endoflife.date client.
func New(userAgent ...string) *Client {
	ua := "enrichment"
	if len(userAgent) > 0 && userAgent[0] != "" {
		ua = userAgent[0]
	}
	return &Client{
		baseURL: "https://endoflife.date/api",
		httpClient: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
		userAgent: ua,
	}
}

// GetAllProducts returns the list of all product names tracked by endoflife.date.
func (c *Client) GetAllProducts(ctx context.Context) ([]string, error) {
	u := fmt.Sprintf("%s/all.json", c.baseURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endoflife: %s", resp.Status)
	}

	var products []string
	if err := json.NewDecoder(resp.Body).Decode(&products); err != nil {
		return nil, err
	}
	return products, nil
}

// GetProduct returns all release cycles for a product.
// The product name should match endoflife.date naming (e.g. "python", "nodejs", "ruby").
func (c *Client) GetProduct(ctx context.Context, product string) ([]Cycle, error) {
	u := fmt.Sprintf("%s/%s.json", c.baseURL, product)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endoflife: %s", resp.Status)
	}

	var cycles []Cycle
	if err := json.NewDecoder(resp.Body).Decode(&cycles); err != nil {
		return nil, err
	}
	return cycles, nil
}

// GetCycle returns lifecycle information for a specific release cycle of a product.
// For example, GetCycle(ctx, "python", "3.12") or GetCycle(ctx, "nodejs", "22").
func (c *Client) GetCycle(ctx context.Context, product, cycle string) (*Cycle, error) {
	u := fmt.Sprintf("%s/%s/%s.json", c.baseURL, product, cycle)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endoflife: %s", resp.Status)
	}

	var result Cycle
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}
