package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/Pirikara/chaingate/internal/ecosystem"
	"github.com/Pirikara/chaingate/internal/ossfmalware"
	"github.com/Pirikara/chaingate/internal/policy"
)

// ThreatIntelCache wraps the OSSF malware client
type ThreatIntelCache struct {
	ossfClient *ossfmalware.Client
}

// NewThreatIntelCache creates a new threat intelligence cache
func NewThreatIntelCache(ossfClient *ossfmalware.Client) *ThreatIntelCache {
	return &ThreatIntelCache{
		ossfClient: ossfClient,
	}
}

// Get retrieves threat intelligence for a package
func (c *ThreatIntelCache) Get(ctx context.Context, pkg ecosystem.PackageIdentity) (*policy.ThreatIntelResult, error) {
	// Query OSSF malicious-packages
	findings, err := c.ossfClient.Lookup(string(pkg.Ecosystem), pkg.Name, pkg.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSSF: %w", err)
	}

	// Convert ossfmalware.MalwareFinding to policy.MalwareFinding
	policyFindings := make([]policy.MalwareFinding, len(findings))
	for i, f := range findings {
		policyFindings[i] = policy.MalwareFinding{
			ID:      f.ID,
			Summary: f.Summary,
			Source:  f.Source,
		}
	}

	return &policy.ThreatIntelResult{
		MalwareFindings: policyFindings,
		LastCheckedAt:   time.Now(),
	}, nil
}
