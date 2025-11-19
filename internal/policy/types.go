package policy

import "time"

// Mode represents the policy enforcement mode
type Mode string

const (
	ModeStrict     Mode = "strict"
	ModeWarn       Mode = "warn"
	ModePermissive Mode = "permissive"
)

// Decision represents the policy decision result
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionBlock Decision = "block"
	DecisionWarn  Decision = "warn"
)

// MalwareFinding represents a malware finding from OSSF
type MalwareFinding struct {
	ID      string `json:"id"`      // e.g., "MAL-2025-32615"
	Summary string `json:"summary"` // Short description
	Source  string `json:"source"`  // "ossf-malicious-packages"
}

// ThreatIntelResult represents the aggregated threat intelligence data
type ThreatIntelResult struct {
	MalwareFindings []MalwareFinding `json:"malware_findings"`
	LastCheckedAt   time.Time        `json:"last_checked_at"`
}
