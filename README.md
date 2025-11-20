# Chain Gate

Chain Gate is a security wrapper for package managers that blocks malicious and vulnerable packages before installation.

## Features

- **Multi-ecosystem support**: Works with npm, Yarn (Classic & Berry), pnpm, gem, bundler, and more
- **Real-time malware detection**: Uses OSSF malicious-packages database (218,000+ entries)
- **Flexible policy modes**: Choose between strict, warn, and permissive modes
- **Transparent MITM proxy**: Intercepts HTTP/HTTPS requests with automatic certificate handling
- **Always up-to-date**: Syncs with OSSF database on every execution (only when upstream changes)
- **Efficient local storage**: Uses bbolt for fast offline lookups
- **CI/CD friendly**: Designed for both local development and CI environments

## Architecture

Chain Gate uses a proxy-based architecture to intercept package manager requests:

1. **CLI Wrapper**: Wraps package manager commands (e.g., `chaingate npm install`)
2. **Local HTTP/HTTPS Proxy**: Intercepts all package download requests
3. **Ecosystem Parser**: Extracts package identity (ecosystem, name, version) from requests
4. **OSSF Malware Database**: Local bbolt database synced from ossf/malicious-packages
5. **Policy Engine**: Decides whether to allow, warn, or block based on policy
6. **Smart Sync**: Checks GitHub HEAD on every execution, only downloads when upstream changes

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed design documentation.

## Installation

### From Source

```bash
go build -o chaingate ./cmd/chaingate
```

### Install to PATH

```bash
go install ./cmd/chaingate
```

## Usage

### Basic Usage

Simply prefix your package manager command with `chaingate`:

```bash
# npm
chaingate -- npm install lodash

# Yarn Classic (v1) or Yarn Berry (v2+)
chaingate -- yarn add react

# pnpm
chaingate -- pnpm install express

# pip (in virtual environment)
chaingate -- pip install requests

# gem
chaingate -- gem install rails
```

### Policy Modes

Chain Gate supports three policy modes:

- **strict** (default): Always blocks malware
- **warn**: Warns about malware but allows installation
- **permissive**: Only logs malware detection, never blocks

```bash
# Strict mode (default)
chaingate --mode=strict npm install

# Warn mode
chaingate --mode=warn npm install

# Permissive mode
chaingate --mode=permissive npm install

# CI mode (always blocks malware regardless of mode)
chaingate --ci npm install
```

### Configuration

Chain Gate requires an ecosystem configuration file. By default, it looks for:

- `./configs/ecosystems.yaml`
- `/etc/chaingate/ecosystems.yaml`

You can specify a custom location:

```bash
chaingate --ecosystems-config=/path/to/ecosystems.yaml npm install
```

### Other Commands

```bash
# Self-check: Verify installation and connectivity
chaingate self-check

# Print current configuration
chaingate print-config
```

### Options

```
Flags:
  --mode string              Policy mode: strict, warn, or permissive (default "strict")
  --ci                       Enable CI mode (always blocks malware)
  --ecosystems-config string Path to ecosystems config file
  --log-level string         Log level: debug, info, warn, error (default "info")
  --data-dir string          Data directory for OSSF database (default "~/.chaingate/feeds/ossf")
  --github-token string      GitHub token for API rate limit (optional, can also use GITHUB_TOKEN env)
```

## How It Works

1. When you run `chaingate -- npm install lodash`, Chain Gate:
   - Checks GitHub for OSSF malicious-packages updates (only syncs if upstream changed)
   - Starts a local MITM proxy on a random port
   - Generates a self-signed CA certificate (cached in `~/.chaingate/certs/`)
   - Runs `npm install lodash` with proxy environment variables:
     - `HTTP_PROXY`, `HTTPS_PROXY`: Proxy URL
     - `YARN_HTTPS_PROXY`: Yarn-specific proxy configuration
     - `NODE_EXTRA_CA_CERTS`: Path to MITM CA certificate for Node.js
   - Intercepts all HTTP/HTTPS requests from the package manager

2. For each package download request:
   - Intercepts the tarball download URL (e.g., `registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`)
   - Extracts package identity (ecosystem, name, version) from the URL pattern
   - Looks up package in local OSSF malware database (bbolt)
   - Checks both exact version matches and semver ranges
   - Applies policy to decide: allow, warn, or block

3. If blocked:
   - Returns HTTP 403 Forbidden to the package manager
   - Displays user-friendly error message with MAL-* IDs and details
   - Package manager fails with an error
   - Installation is prevented

4. If allowed or warned:
   - Proxies the request to the actual registry
   - Package is downloaded and installed normally
   - Warnings are displayed but don't block installation

## Threat Intelligence Sources

- **OSSF malicious-packages**: Community-maintained malware database by the Open Source Security Foundation
  - Repository: [github.com/ossf/malicious-packages](https://github.com/ossf/malicious-packages)
  - Coverage: 218,000+ malicious package entries across npm, PyPI, and other ecosystems
  - Format: OSV (Open Source Vulnerability) schema
  - Updates: Synced from GitHub on every execution (only downloads when changed)

## Logs

Chain Gate outputs structured JSON logs for easy parsing:

```json
{
  "ts": "2025-11-19T14:43:07.123Z",
  "level": "info",
  "event": "package_check",
  "ecosystem": "npm",
  "name": "safe-chain-test",
  "version": "1.0.0",
  "malware_findings": [
    {
      "id": "MAL-2025-32615",
      "summary": "Malicious code in safe-chain-test (npm)",
      "source": "ossf-malicious-packages"
    }
  ],
  "decision": "block",
  "mode": "strict",
  "ci": false,
  "request_id": "uuid-..."
}
```

## Exit Codes

- `0`: Success (package manager succeeded)
- `1`: Tool internal error (config error, proxy failure, etc.)
- `2`: Blocked due to malware or policy violation
- `3`: Failed to query threat intelligence (depends on policy)

## Supported Ecosystems

### Current Support

- **npm**: npm, Yarn Classic (v1.x), Yarn Berry (v2+/v4.x), pnpm
  - Registries: `registry.npmjs.org`, `registry.yarnpkg.com`
  - Detection: Tarball URLs with pattern matching
- **PyPI**: pip, uv, poetry
  - Registries: `files.pythonhosted.org`
  - Detection: Wheel and source distribution downloads
  - Features: PEP 503 package name normalization
- **RubyGems**: gem, bundler
  - Registries: `rubygems.org`
  - Detection: Gem file downloads

### Tested Package Managers

| Package Manager | Version | Status |
|----------------|---------|--------|
| npm | 10.x | ✅ Working |
| Yarn Classic | 1.x | ✅ Working |
| Yarn Berry | 4.11.0 | ✅ Working |
| pnpm | 9.x | ✅ Working |
| pip | 24.x | ✅ Working |
| uv | 0.6.x | ✅ Working |
| poetry | 2.x | ✅ Working |
| gem | 3.x | ✅ Working |

### Known Limitations

- **Yarn Berry**: Requires `NODE_EXTRA_CA_CERTS` for MITM certificate trust
- **Cached packages**: If a package is already cached locally, it won't be checked again
- **pip**: Requires virtual environment for proper proxy configuration

## Development

### Project Structure

```
chaingate/
├── cmd/
│   └── chaingate/        # CLI entry point
├── internal/
│   ├── proxy/            # HTTP/HTTPS proxy server
│   ├── ecosystem/        # Ecosystem config and parser
│   ├── ossfmalware/      # OSSF malicious-packages client
│   ├── cache/            # Threat intelligence cache (wrapper)
│   ├── policy/           # Policy engine
│   └── logger/           # JSON logging
├── configs/
│   └── ecosystems.yaml   # Ecosystem patterns
└── ARCHITECTURE.md       # Detailed design docs
```

### Building

```bash
go build -o chaingate ./cmd/chaingate
```

### Testing

```bash
# Test self-check (syncs OSSF database and verifies malware detection)
./chaingate self-check

# Test detection with a package in the OSSF database
# Note: Most malicious packages are removed from registries,
# so testing requires packages still listed in OSSF database

# Test with Yarn Berry
./chaingate -- yarn add <package>

# Test with pnpm
./chaingate -- pnpm add <package>

# Test different policy modes
./chaingate --mode=strict -- npm install <package>  # Blocks malware
./chaingate --mode=warn -- npm install <package>    # Warns about malware
./chaingate --mode=permissive -- npm install <package>  # Only logs

# Run unit tests
go test ./...
```

## License

[To be determined]

## Acknowledgments

- **Open Source Security Foundation (OSSF)**: For maintaining the malicious-packages database
- **bbolt**: For the reliable embedded database
