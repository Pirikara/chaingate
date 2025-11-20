package policy

import (
	"github.com/Pirikara/chaingate/internal/ecosystem"
)

// Engine makes policy decisions
type Engine struct {
	mode Mode
	isCI bool
}

// NewEngine creates a new policy engine
func NewEngine(mode Mode, isCI bool) *Engine {
	return &Engine{
		mode: mode,
		isCI: isCI,
	}
}

// PolicyInput represents input to the policy engine
type PolicyInput struct {
	Intel           *ThreatIntelResult
	PackageIdentity ecosystem.PackageIdentity
}

// PolicyResult represents the result of a policy decision
type PolicyResult struct {
	Decision Decision
	Reason   string
}

// Evaluate evaluates a policy and returns a decision
func (e *Engine) Evaluate(input PolicyInput) PolicyResult {
	// Rule 1: Malware is always blocked in strict or CI mode
	hasMalware := len(input.Intel.MalwareFindings) > 0

	if hasMalware {
		// CI mode overrides: always block malware in CI regardless of mode
		if e.isCI {
			return PolicyResult{
				Decision: DecisionBlock,
				Reason:   "Package is identified as malware by OSSF malicious-packages (CI mode)",
			}
		}

		switch e.mode {
		case ModeStrict:
			// Strict mode: always block malware
			return PolicyResult{
				Decision: DecisionBlock,
				Reason:   "Package is identified as malware by OSSF malicious-packages",
			}

		case ModeWarn:
			// Warn mode: only warn on malware
			return PolicyResult{
				Decision: DecisionWarn,
				Reason:   "Package is identified as malware by OSSF malicious-packages",
			}

		case ModePermissive:
			// Permissive mode: only warn, never block
			return PolicyResult{
				Decision: DecisionWarn,
				Reason:   "Package is identified as malware by OSSF malicious-packages",
			}
		}
	}

	// Default: allow
	return PolicyResult{
		Decision: DecisionAllow,
		Reason:   "No threats detected",
	}
}

// ShouldBlock returns true if the decision is to block
func (pr PolicyResult) ShouldBlock() bool {
	return pr.Decision == DecisionBlock
}

// ShouldWarn returns true if the decision is to warn
func (pr PolicyResult) ShouldWarn() bool {
	return pr.Decision == DecisionWarn
}

// SetMode sets the policy mode
func (e *Engine) SetMode(mode Mode) {
	e.mode = mode
}

// SetCI sets the CI flag
func (e *Engine) SetCI(isCI bool) {
	e.isCI = isCI
}

// GetMode returns the current mode
func (e *Engine) GetMode() Mode {
	return e.mode
}

// IsCI returns the CI flag
func (e *Engine) IsCI() bool {
	return e.isCI
}
