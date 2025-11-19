package ecosystem

import (
	"net/url"
	"regexp"
	"strings"
)

// Detector detects package identity from HTTP requests
type Detector struct {
	config *Config
}

// NewDetector creates a new Detector
func NewDetector(config *Config) *Detector {
	return &Detector{config: config}
}

// DetectFromRequest attempts to detect package identity from host and path
func (d *Detector) DetectFromRequest(host, path string) *PackageIdentity {
	for _, eco := range d.config.Ecosystems {
		if !d.hostMatches(host, eco.Hosts) {
			continue
		}

		for _, pattern := range eco.Patterns {
			identity := d.tryPattern(eco.ID, pattern, path)
			if identity != nil {
				return identity
			}
		}
	}

	return nil
}

// hostMatches checks if the host matches any of the configured hosts
func (d *Detector) hostMatches(host string, configHosts []string) bool {
	for _, configHost := range configHosts {
		// Remove port if present
		hostWithoutPort := host
		if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
			hostWithoutPort = host[:colonIdx]
		}

		// Wildcard matching
		if strings.HasPrefix(configHost, "*.") {
			suffix := configHost[1:] // Remove *
			if strings.HasSuffix(hostWithoutPort, suffix) || hostWithoutPort == configHost[2:] {
				return true
			}
		} else if hostWithoutPort == configHost {
			return true
		}
	}
	return false
}

// tryPattern attempts to extract package identity using the given pattern
func (d *Detector) tryPattern(ecoID EcosystemID, pattern PatternConfig, path string) *PackageIdentity {
	matches := pattern.compiledRegex.FindStringSubmatch(path)
	if matches == nil {
		return nil
	}

	// Create a map of named capture groups
	result := make(map[string]string)
	for i, name := range pattern.compiledRegex.SubexpNames() {
		if i != 0 && name != "" && i < len(matches) {
			result[name] = matches[i]
		}
	}

	var name, version string

	// Extract using name_version_from_file_regex
	if pattern.Extract.NameVersionFromFileRegex != "" {
		file, ok := result["file"]
		if !ok {
			return nil
		}

		nvRegex, err := regexp.Compile(pattern.Extract.NameVersionFromFileRegex)
		if err != nil {
			return nil
		}

		nvMatches := nvRegex.FindStringSubmatch(file)
		if nvMatches == nil {
			return nil
		}

		nvResult := make(map[string]string)
		for i, n := range nvRegex.SubexpNames() {
			if i != 0 && n != "" && i < len(nvMatches) {
				nvResult[n] = nvMatches[i]
			}
		}

		name = nvResult["name"]
		version = nvResult["version"]
	} else if pattern.Extract.VersionFromFileRegex != "" {
		// Extract version from file, name from package
		file, fileOk := result["file"]
		pkg, pkgOk := result["package"]
		if !fileOk || !pkgOk {
			return nil
		}

		// Handle scoped packages (@scope%2Fname)
		if scope, ok := result["scope"]; ok {
			scopeName := result["name"]
			// URL decode and construct scoped package name
			decodedScope, _ := url.QueryUnescape(scope)
			name = decodedScope + "/" + scopeName
		} else {
			// URL decode package name
			name, _ = url.QueryUnescape(pkg)
		}

		// Extract version by removing package name prefix from filename
		// For example: file="safe-chain-test-0.0.1-security", pkg="safe-chain-test" → version="0.0.1-security"
		expectedPrefix := pkg + "-"
		if strings.HasPrefix(file, expectedPrefix) {
			version = strings.TrimPrefix(file, expectedPrefix)
		} else {
			// Fallback to regex if prefix doesn't match
			vRegex, err := regexp.Compile(pattern.Extract.VersionFromFileRegex)
			if err != nil {
				return nil
			}

			vMatches := vRegex.FindStringSubmatch(file)
			if vMatches == nil {
				return nil
			}

			vResult := make(map[string]string)
			for i, n := range vRegex.SubexpNames() {
				if i != 0 && n != "" && i < len(vMatches) {
					vResult[n] = vMatches[i]
				}
			}
			version = vResult["version"]
		}
	} else {
		// Direct extraction from path
		var ok bool
		name, ok = result["name"]
		if !ok {
			name, ok = result["package"]
		}
		if !ok {
			return nil
		}

		version, ok = result["version"]
		if !ok {
			// Version not available in this request type
			return nil
		}

		name, _ = url.QueryUnescape(name)
	}

	if name == "" || version == "" {
		return nil
	}

	// Clean version (remove known package file extensions only)
	// Don't use filepath.Ext() as it incorrectly treats version numbers like "0.0.1" as extensions
	knownExtensions := []string{".tgz", ".tar.gz", ".gem", ".whl", ".zip"}
	for _, ext := range knownExtensions {
		if strings.HasSuffix(version, ext) {
			version = strings.TrimSuffix(version, ext)
			break
		}
	}

	return &PackageIdentity{
		Ecosystem: ecoID,
		Name:      name,
		Version:   version,
	}
}
