package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/casuncio/bouncer-engine/internal/store"
)

// PolicyProvider interface defines how engine fetchs active rules
type PolicyProvider interface {
	ListActivePolicies(ctx context.Context) ([]store.Policy, error)
}

// EvaluationRequest represents an incoming Authorization check
type EvaluationRequest struct {
	PrincipalID           string
	PrincipalAttributes   map[string][]string
	ResourceType          string
	ResourceID            string
	ResourceAttributes    map[string][]string
	Action                string
	EnvironmentAttributes map[string][]string
}

// EvaluationResponse represents descision returned to the client.
type EvaluationResponse struct {
	Allowed          bool
	MatchedPolicyID  string
	Reason           string
	EvaluationTimeNs int64
}

// FlattenAttributes merges all contextual attributes into a single map with
// dot-notaton prefixes for keys, principal.<> resource.<> environment.<>
func (req *EvaluationRequest) FlattenAttributes() map[string][]string {
	attrMap := make(map[string][]string)

	for k, v := range req.PrincipalAttributes {
		attrMap[fmt.Sprintf("principal.%s", k)] = v
	}

	for k, v := range req.ResourceAttributes {
		attrMap[fmt.Sprintf("resource.%s", k)] = v
	}

	for k, v := range req.EnvironmentAttributes {
		attrMap[fmt.Sprintf("environment.%s", k)] = v
	}
	return attrMap
}

// Engine holds the dependencies for evaluation
type Engine struct {
	provider PolicyProvider
}

// New creates a new Engine instance, injected with a PolicyProvider
func New(provider PolicyProvider) *Engine {
	return &Engine{
		provider: provider,
	}
}

func (engine *Engine) CheckAccess(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
	startTime := time.Now()

	flatAttr := req.FlattenAttributes()

	// fetch policies
	policies, err := engine.provider.ListActivePolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	// evaluate each policy
	for _, policy := range policies {
		if (policy.Target.ResourceType != req.ResourceType) || (policy.Target.Action != req.Action) {
			continue // this policy does not apply, skip
		}

		// Evaluate conditions for this policy they must all evaluate to true
		allCondMet := true
		for _, cond := range policy.Conditions {
			if !EvaluateCondition(cond, flatAttr) {
				allCondMet = false
				break // no need to check rest of conditions, this policy does not match
			}
		}

		// Policy matched all conditions are met
		if allCondMet {
			return &EvaluationResponse{
				Allowed:          (policy.Access == store.AccessAllow),
				MatchedPolicyID:  policy.ID,
				Reason:           fmt.Sprintf("Matched policy: %s", policy.Description),
				EvaluationTimeNs: int64(time.Since(startTime)),
			}, nil
		}
	}

	// Deny by Default, no policies match
	return &EvaluationResponse{
		Allowed:          false,
		MatchedPolicyID:  "",
		Reason:           "Implict Deny: No matching polices",
		EvaluationTimeNs: int64(time.Since(startTime)),
	}, nil

}
