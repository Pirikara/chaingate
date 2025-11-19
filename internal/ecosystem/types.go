package ecosystem

// EcosystemID represents a package ecosystem identifier
type EcosystemID string

const (
	EcosystemNPM      EcosystemID = "npm"
	EcosystemRubyGems EcosystemID = "RubyGems"
	EcosystemPyPI     EcosystemID = "PyPI"
	EcosystemCratesIO EcosystemID = "crates.io"
	EcosystemGo       EcosystemID = "Go"
)

// PackageIdentity represents a unique package identification
type PackageIdentity struct {
	Ecosystem EcosystemID `json:"ecosystem"`
	Name      string      `json:"name"`
	Version   string      `json:"version"`
}

// String returns a string representation of the package identity
func (p PackageIdentity) String() string {
	return string(p.Ecosystem) + ":" + p.Name + "@" + p.Version
}
