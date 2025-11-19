package ecosystem

import (
	"regexp"
	"testing"
)

func TestDetector_DetectFromRequest(t *testing.T) {
	config := &Config{
		Ecosystems: []EcosystemConfig{
			{
				ID:    EcosystemNPM,
				Hosts: []string{"registry.npmjs.org", "*.npmjs.org"},
				Patterns: []PatternConfig{
					{
						Name:      "npm-tarball",
						PathRegex: "^/(?P<package>[^/]+)/-/(?P<file>[^/]+)\\.tgz$",
						Extract: ExtractConfig{
							VersionFromFileRegex: "^[^-]+-(?P<version>.+)$",
						},
					},
					{
						Name:      "npm-scoped-tarball",
						PathRegex: "^/(?P<scope>@[^/]+)%2[Ff](?P<name>[^/]+)/-/(?P<file>[^/]+)\\.tgz$",
						Extract: ExtractConfig{
							VersionFromFileRegex: "^[^-]+-(?P<version>.+)$",
						},
					},
				},
			},
			{
				ID:    EcosystemRubyGems,
				Hosts: []string{"rubygems.org", "*.rubygems.org"},
				Patterns: []PatternConfig{
					{
						Name:      "rubygems-gem",
						PathRegex: "^/downloads/(?P<file>[^/]+)\\.gem$",
						Extract: ExtractConfig{
							NameVersionFromFileRegex: "^(?P<name>.+)-(?P<version>[0-9][^-]+)$",
						},
					},
				},
			},
		},
	}

	// Compile regex patterns
	for i := range config.Ecosystems {
		for j := range config.Ecosystems[i].Patterns {
			pattern := &config.Ecosystems[i].Patterns[j]
			regex, err := compileRegex(pattern.PathRegex)
			if err != nil {
				t.Fatalf("Failed to compile regex: %v", err)
			}
			pattern.compiledRegex = regex
		}
	}

	detector := NewDetector(config)

	tests := []struct {
		name     string
		host     string
		path     string
		want     *PackageIdentity
		wantNil  bool
	}{
		{
			name: "npm regular package",
			host: "registry.npmjs.org",
			path: "/lodash/-/lodash-4.17.21.tgz",
			want: &PackageIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "lodash",
				Version:   "4.17.21",
			},
		},
		{
			name: "npm scoped package",
			host: "registry.npmjs.org",
			path: "/@babel%2Fcore/-/core-7.20.0.tgz",
			want: &PackageIdentity{
				Ecosystem: EcosystemNPM,
				Name:      "@babel/core",
				Version:   "7.20.0",
			},
		},
		{
			name: "rubygems package",
			host: "rubygems.org",
			path: "/downloads/rails-7.1.0.gem",
			want: &PackageIdentity{
				Ecosystem: EcosystemRubyGems,
				Name:      "rails",
				Version:   "7.1.0",
			},
		},
		{
			name:    "unknown host",
			host:    "unknown.example.com",
			path:    "/some/path",
			wantNil: true,
		},
		{
			name:    "metadata request (no version)",
			host:    "registry.npmjs.org",
			path:    "/lodash",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.DetectFromRequest(tt.host, tt.path)
			if tt.wantNil {
				if got != nil {
					t.Errorf("DetectFromRequest() = %v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatalf("DetectFromRequest() = nil, want %v", tt.want)
			}

			if got.Ecosystem != tt.want.Ecosystem {
				t.Errorf("Ecosystem = %v, want %v", got.Ecosystem, tt.want.Ecosystem)
			}
			if got.Name != tt.want.Name {
				t.Errorf("Name = %v, want %v", got.Name, tt.want.Name)
			}
			if got.Version != tt.want.Version {
				t.Errorf("Version = %v, want %v", got.Version, tt.want.Version)
			}
		})
	}
}

func compileRegex(pattern string) (*regexp.Regexp, error) {
	// This is a helper function for testing
	// In actual code, this is done in LoadConfig
	return regexp.Compile(pattern)
}
