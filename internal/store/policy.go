package store

import (
	"fmt"
	"regexp"
)

// Access, the outcome of matched policy
type Access string

const (
	AccessAllow Access = "ALLOW"
	AccessDeny  Access = "DENY"
)

// Policy represents a single Attribute-Based Access Control rule
type Policy struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	Access      Access      `json:"access"`
	Target      Target      `json:"target"`
	Conditions  []Condition `json:"conditions"`
}

// Target represents scope of the policy,
// access for action on a specific resource
type Target struct {
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
}

// Condition defines a specific dynamic rule that must be met
type Condition struct {
	Attribute string   `json:"attribute"`
	Operator  string   `json:"operator"`
	Value     []string `json:"value"`

	// Pointer to store compiled regex
	CompiledRegex *regexp.Regexp `json:"-"`
}

// Compile prepares the policy for high-speed evaluation by pre-compiling
// any heavy resources (like REGEX patterns) before it enters the in-memory cache.
func (p *Policy) Compile() error {
	for i := range p.Conditions {
		cond := &p.Conditions[i]
		if cond.Operator != "REGEX" || len(cond.Value) == 0 {
			continue
		}

		compiled, err := regexp.Compile(cond.Value[0])
		if err != nil {
			return fmt.Errorf("policy %s: invalid regex %q: %w", p.ID, cond.Value[0], err)
		}
		cond.CompiledRegex = compiled
	}
	return nil
}
