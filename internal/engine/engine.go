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
	policies, err := engine.provider.ListActivePolicies(ctx)
	if err != nil {
		return EvaluationResponse{}, fmt.Errorf("failed to list policies: %w", err)
	}

	// evaluate each policy
	for _, policy := range policies {
		if (policy.Target.ResourceType != req.ResourceType) || (policy.Target.Action != req.Action) {
			continue // this policy does not apply, skip
		}

		// Evaluate conditions for this policy they must all evaluate to true
		allCondsMet := true
		for _, cond := range policy.Conditions {
			// Pass the raw request instead of a flattened map
			if !EvaluateCondition(cond, req) {
				allCondsMet = false
				break
			}
		}

		// Policy matched all conditions are met
		if allCondsMet {
			return EvaluationResponse{
				Allowed:          (policy.Access == store.AccessAllow),
				MatchedPolicyID:  policy.ID,
				Reason:           "Matched policy",
				EvaluationTimeNs: int64(time.Since(startTime)),
			}, nil
		}
	}

	// Deny by Default, no policies match
	return EvaluationResponse{
		Allowed:          false,
		MatchedPolicyID:  "",
		Reason:           "Implict Deny: No matching polices",
		EvaluationTimeNs: int64(time.Since(startTime)),
	}, nil

}
