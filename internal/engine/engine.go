package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/casuncio/bouncer-engine/internal/store"
)

// PolicyProvider interface defines how engine fetchs active rules
type PolicyProvider interface {
	ListActivePolicies(ctx context.Context) (store.PolicySnapshot, error)
}

// EvaluationRequest represents an incoming Authorization check
type EvaluationRequest struct {
	PrincipalID           string              `json:"principal_id"`
	PrincipalAttributes   map[string][]string `json:"principal_attributes"`
	ResourceType          string              `json:"resource_type"`
	ResourceID            string              `json:"resource_id"`
	ResourceAttributes    map[string][]string `json:"resource_attributes"`
	Action                string              `json:"action"`
	EnvironmentAttributes map[string][]string `json:"environment_attributes"`
}

// EvaluationResponse represents descision returned to the client.
type EvaluationResponse struct {
	Allowed          bool
	MatchedPolicyID  string
	Reason           string
	EvaluationTimeNs int64
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

func (engine *Engine) CheckAccess(ctx context.Context, req *EvaluationRequest) (EvaluationResponse, error) {
	startTime := time.Now()

	// fetch policies
	snapshot, err := engine.provider.ListActivePolicies(ctx)
	if err != nil {
		return EvaluationResponse{}, fmt.Errorf("failed to list policies: %w", err)
	}

	// Phase 1: Explicit deny overrides everything. A matching deny policy
	// short-circuits before allow policies are considered.
	if policy, matched := firstMatch(snapshot.Deny, req); matched {
		return EvaluationResponse{
			Allowed:          false,
			MatchedPolicyID:  policy.ID,
			Reason:           "Explicit Deny: Matched deny policy",
			EvaluationTimeNs: int64(time.Since(startTime)),
		}, nil
	}

	// Phase 2: Allow policies. First matching allow policy grants access.
	if policy, matched := firstMatch(snapshot.Allow, req); matched {
		return EvaluationResponse{
			Allowed:          true,
			MatchedPolicyID:  policy.ID,
			Reason:           "Matched Policy",
			EvaluationTimeNs: int64(time.Since(startTime)),
		}, nil
	}

	// Deny by Default, no policies match
	return EvaluationResponse{
		Allowed:          false,
		MatchedPolicyID:  "",
		Reason:           "Implict Deny: No matching polices",
		EvaluationTimeNs: int64(time.Since(startTime)),
	}, nil

}

// firstMatch returns the first policy in the slice whose target matches the
// request and whose conditions all evaluate to true. Condition evaluation is
// shared across allow and deny phases so every operator is reusable.
func firstMatch(policies []store.Policy, req *EvaluationRequest) (store.Policy, bool) {
	for _, policy := range policies {
		if (policy.Target.ResourceType != req.ResourceType) || (policy.Target.Action != req.Action) {
			continue
		}

		allCondsMet := true
		for _, cond := range policy.Conditions {
			if !EvaluateCondition(cond, req) {
				allCondsMet = false
				break
			}
		}

		if allCondsMet {
			return policy, true
		}
	}

	return store.Policy{}, false
}
