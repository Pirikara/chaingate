package policy

import (
	"testing"
	"time"

	"github.com/Pirikara/chaingate/internal/ecosystem"
)

func TestEngine_Evaluate(t *testing.T) {
	tests := []struct {
		name           string
		mode           Mode
		isCI           bool
		intel          *ThreatIntelResult
		wantDecision   Decision
		wantShouldBlock bool
	}{
		{
			name: "strict mode blocks malware",
			mode: ModeStrict,
			intel: &ThreatIntelResult{
				MalwareFindings: []MalwareFinding{
					{
						ID:      "MAL-2025-32615",
						Summary: "Malicious code detected",
						Source:  "ossf-malicious-packages",
					},
				},
				LastCheckedAt: time.Now(),
			},
			wantDecision:   DecisionBlock,
			wantShouldBlock: true,
		},
		{
			name: "warn mode warns about malware",
			mode: ModeWarn,
			intel: &ThreatIntelResult{
				MalwareFindings: []MalwareFinding{
					{
						ID:      "MAL-2025-32615",
						Summary: "Malicious code detected",
						Source:  "ossf-malicious-packages",
					},
				},
				LastCheckedAt: time.Now(),
			},
			wantDecision:   DecisionWarn,
			wantShouldBlock: false,
		},
		{
			name: "permissive mode warns about malware",
			mode: ModePermissive,
			intel: &ThreatIntelResult{
				MalwareFindings: []MalwareFinding{
					{
						ID:      "MAL-2025-32615",
						Summary: "Malicious code detected",
						Source:  "ossf-malicious-packages",
					},
				},
				LastCheckedAt: time.Now(),
			},
			wantDecision:   DecisionWarn,
			wantShouldBlock: false,
		},
		{
			name: "CI mode always blocks malware",
			mode: ModeWarn,
			isCI: true,
			intel: &ThreatIntelResult{
				MalwareFindings: []MalwareFinding{
					{
						ID:      "MAL-2025-32615",
						Summary: "Malicious code detected",
						Source:  "ossf-malicious-packages",
					},
				},
				LastCheckedAt: time.Now(),
			},
			wantDecision:   DecisionBlock,
			wantShouldBlock: true,
		},
		{
			name: "clean package allowed",
			mode: ModeStrict,
			intel: &ThreatIntelResult{
				MalwareFindings: []MalwareFinding{},
				LastCheckedAt:   time.Now(),
			},
			wantDecision:   DecisionAllow,
			wantShouldBlock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine(tt.mode, tt.isCI)

			input := PolicyInput{
				Intel: tt.intel,
				PackageIdentity: ecosystem.PackageIdentity{
					Ecosystem: ecosystem.EcosystemNPM,
					Name:      "test-package",
					Version:   "1.0.0",
				},
			}

			result := engine.Evaluate(input)

			if result.Decision != tt.wantDecision {
				t.Errorf("Decision = %v, want %v", result.Decision, tt.wantDecision)
			}

			if result.ShouldBlock() != tt.wantShouldBlock {
				t.Errorf("ShouldBlock() = %v, want %v", result.ShouldBlock(), tt.wantShouldBlock)
			}
		})
	}
}
