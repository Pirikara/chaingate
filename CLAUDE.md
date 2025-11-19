# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Chain Gate is a security wrapper for package managers that blocks malicious packages before installation using a MITM proxy architecture. It uses the OSSF malicious-packages database (218,000+ entries) to detect malware in real-time.

## Build & Test Commands

```bash
# Build the binary
go build -o chaingate cmd/chaingate/main.go

# Run tests
go test ./...

# Run specific package tests
go test ./internal/ecosystem
go test ./internal/policy

# Run with verbose output
go test -v ./internal/ossfmalware

# Self-check (syncs OSSF database and verifies)
./chaingate self-check

# Test with actual package manager
./chaingate -- npm install <package>
```

## Architecture

### Request Flow
1. **CLI Wrapper** (`cmd/chaingate/main.go`) starts MITM proxy and wraps package manager command
2. **MITM Proxy** (`internal/proxy/proxy_mitm.go`) intercepts HTTP/HTTPS requests using self-signed CA
3. **Ecosystem Detector** (`internal/ecosystem/detector.go`) parses URLs to extract package identity (ecosystem, name, version)
4. **OSSF Client** (`internal/ossfmalware/client.go`) looks up package in local bbolt database
5. **Policy Engine** (`internal/policy/engine.go`) decides to allow/warn/block based on mode
6. **Logger** (`internal/logger/logger.go`) outputs structured JSON logs

### Key Components

**OSSF Malware Detection** (`internal/ossfmalware/`):
- **client.go**: Main interface with `EnsureUpdated()`, `Lookup()`, `SelfCheck()`
- **github.go**: Checks GitHub HEAD SHA and downloads tarballs from ossf/malicious-packages
- **downloader.go**: Extracts tarball, parses OSV JSON files, handles semver range matching
- **index.go**: bbolt database management with efficient lookups (ecosystem/name → version → findings)
- **types.go**: OSV format types (OSVEntry, Affected, Range, MalwareFinding)

**Smart Sync Strategy**:
- On every execution, checks GitHub HEAD commit SHA
- Only downloads/syncs when upstream has changed
- Local bbolt database enables fast offline lookups
- Data stored in `~/.chaingate/feeds/ossf/malware.db`

**Ecosystem Detection** (`internal/ecosystem/`):
- `ecosystems.yaml` defines URL patterns for each package manager
- Detector uses regex to parse tarball URLs and extract package identity
- Supports npm (including Yarn Berry), RubyGems, with patterns for scoped packages

**MITM Proxy Details**:
- Uses `github.com/elazarl/goproxy` for HTTP/HTTPS interception
- Generates self-signed CA cert cached in `~/.chaingate/certs/`
- Sets environment variables: `HTTP_PROXY`, `HTTPS_PROXY`, `YARN_HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`
- Only intercepts known registry hosts (npm, yarn, rubygems, pypi)

**Policy Modes**:
- **strict** (default): Always blocks malware
- **warn**: Warns about malware but allows installation
- **permissive**: Only logs, never blocks
- **CI mode**: Overrides to always block regardless of mode setting

### Data Flow for Package Check

```
Package Manager Request
  ↓
MITM Proxy Intercepts
  ↓
Ecosystem Detector (URL → PackageIdentity)
  ↓
Cache.Get() → ossfmalware.Lookup(ecosystem, name, version)
  ↓
bbolt Index Lookup + Semver Range Matching
  ↓
Policy Engine Evaluates (malware_findings → Decision)
  ↓
Logger outputs JSON + HTTP 403 (if blocked) or passthrough
```

## Important Implementation Details

### Adding New Ecosystem Support
1. Add patterns to `cmd/chaingate/ecosystems.yaml`
2. Add registry hosts to `knownRegistries` in `internal/proxy/proxy_mitm.go`
3. Test URL parsing with actual registry URLs

### Ecosystem YAML Pattern Format
```yaml
- name: "pattern-name"
  path_regex: "^/(?P<package>[^/]+)/-/(?P<file>[^/]+)\\.tgz$"
  extract:
    version_from_file_regex: "^[^-]+-(?P<version>.+)$"
```

Named groups in `path_regex` are used directly. If version is in filename, use `version_from_file_regex` to extract it.

### OSSF Database Structure
- **Buckets**: `pkgs` (package index), `meta` (sync metadata), `entries` (full OSV entries)
- **Key Format**: `ecosystem/name` → serialized `map[version][]MalwareFinding`
- **Range Matching**: Full OSV entries cached in memory for semver range checks

### Version Matching Logic
1. Check exact version match in index first (O(1) lookup)
2. If no exact match, iterate cached OSV entries and check ranges
3. Supports OSV range types: SEMVER, ECOSYSTEM, GIT
4. Uses `github.com/Masterminds/semver/v3` for semver comparison

### Logging Format
All events output as JSON with standard fields:
- `ts`: RFC3339Nano timestamp
- `level`: info/warn/error/debug
- `event`: Event type (package_check, proxy_start, etc.)
- Package check events include `malware_findings` array with MAL-* IDs

## Testing Notes

- Most malicious packages are removed from registries after detection
- `safe-chain-test` was test malware but now only version `0.0.1-security` exists
- Self-check verifies detection against packages still in OSSF database
- Test with `--log-level=debug` to see detailed request flow
- The malicious-packages/ directory is the cloned OSSF repository for reference

## Environment Variables

- `GITHUB_TOKEN`: Optional, increases GitHub API rate limit for sync
- Set automatically by chaingate: `HTTP_PROXY`, `HTTPS_PROXY`, `YARN_HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`
