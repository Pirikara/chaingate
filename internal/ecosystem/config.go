package ecosystem

import (
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Config represents the ecosystems configuration
type Config struct {
	Ecosystems []EcosystemConfig `yaml:"ecosystems"`
}

// EcosystemConfig represents a single ecosystem configuration
type EcosystemConfig struct {
	ID       EcosystemID     `yaml:"id"`
	Hosts    []string        `yaml:"hosts"`
	Patterns []PatternConfig `yaml:"patterns"`
}

// PatternConfig represents a URL pattern configuration
type PatternConfig struct {
	Name      string        `yaml:"name"`
	PathRegex string        `yaml:"path_regex"`
	Extract   ExtractConfig `yaml:"extract"`

	// Compiled regex (not in YAML)
	compiledRegex *regexp.Regexp
}

// ExtractConfig represents extraction rules
type ExtractConfig struct {
	VersionFromFileRegex       string `yaml:"version_from_file_regex"`
	NameVersionFromFileRegex   string `yaml:"name_version_from_file_regex"`
}

// LoadConfig loads ecosystem configuration with 3-level fallback:
// 1. Explicit path (--ecosystems-config flag)
// 2. Home directory (~/.chaingate/ecosystems.yaml)
// 3. Embedded default (passed as defaultData)
func LoadConfig(path string, defaultData []byte) (*Config, error) {
	var data []byte
	var err error

	// Level 1: Explicit path (for development/debugging)
	if path != "" {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
	} else {
		// Level 2: Home directory (for advanced users)
		home, err := os.UserHomeDir()
		if err == nil {
			homeConfig := filepath.Join(home, ".chaingate", "ecosystems.yaml")
			if fileExists(homeConfig) {
				data, err = os.ReadFile(homeConfig)
				if err == nil {
					// Successfully loaded from home directory
					goto parseConfig
				}
			}
		}

		// Level 3: Embedded default (for 99% of users)
		data = defaultData
	}

parseConfig:
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Compile all regex patterns
	for i := range config.Ecosystems {
		for j := range config.Ecosystems[i].Patterns {
			pattern := &config.Ecosystems[i].Patterns[j]
			regex, err := regexp.Compile(pattern.PathRegex)
			if err != nil {
				return nil, err
			}
			pattern.compiledRegex = regex
		}
	}

	return &config, nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
