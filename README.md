# enrichment

A Go library for fetching package metadata from multiple sources using [PURLs](https://github.com/package-url/purl-spec). It queries the [ecosyste.ms](https://ecosyste.ms) API, [deps.dev](https://deps.dev), or package registries directly, and returns a unified `PackageInfo` struct with license, version, description, repository, and changelog information.

## Install

```
go get github.com/git-pkgs/enrichment
```

## Usage

```go
client, err := enrichment.NewClient()
if err != nil {
    log.Fatal(err)
}

// Look up multiple packages at once
results, err := client.BulkLookup(ctx, []string{
    "pkg:npm/lodash",
    "pkg:pypi/requests",
})

// Get all versions of a package
versions, err := client.GetVersions(ctx, "pkg:npm/lodash")

// Get a specific version
version, err := client.GetVersion(ctx, "pkg:npm/lodash@4.17.21")
```

By default `NewClient` uses a hybrid strategy: PURLs with a `repository_url` qualifier go straight to the registry, everything else goes through ecosyste.ms. Set `GIT_PKGS_DIRECT=1` or `git config --global pkgs.direct true` to skip ecosyste.ms and query all registries directly.

You can also construct a specific client if you want to control the source:

```go
eco, _ := enrichment.NewEcosystemsClient()  // ecosyste.ms API only
reg := enrichment.NewRegistriesClient()      // direct registry queries only
dep := enrichment.NewDepsDevClient()         // deps.dev API only
```

## Scorecard

The `scorecard` sub-package queries the [OpenSSF Scorecard](https://securityscorecards.dev) API for repository-level security scores.

```go
client := scorecard.New()
result, err := client.GetScore(ctx, "github.com/lodash/lodash")
fmt.Println(result.Score) // 6.8
```

## End of Life

The `endoflife` sub-package queries the [endoflife.date](https://endoflife.date) API for product lifecycle data -- release dates, EOL dates, LTS status, and support windows.

```go
client := endoflife.New()

// All tracked products
products, err := client.GetAllProducts(ctx)

// All release cycles for a product
cycles, err := client.GetProduct(ctx, "nodejs")
for _, c := range cycles {
    fmt.Printf("%s: eol=%v lts=%v\n", c.Name, c.IsEOL(), c.IsLTS())
}

// Single cycle
cycle, err := client.GetCycle(ctx, "python", "3.12")
fmt.Println(cycle.Latest, cycle.IsEOL())
```

The `eol`, `lts`, `support`, and `extendedSupport` fields from the API can be either a date or a boolean. The `DateOrBool` type handles both, and the `IsEOL()`, `IsSupported()`, and `IsLTS()` methods on `Cycle` do the right thing regardless.

## License

MIT
