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

## License

MIT
