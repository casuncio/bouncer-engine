package store

import (
	"context"
	"maps"
	"sync/atomic"
)

// PolicyMap type alias for underlying map
type PolicyMap map[string]Policy

// PolicyStore manages the in-memory cache of ABAC rules, uses lock-free atomic pointers.
type PolicyStore struct {
	// atomic pointer to a PolicyMap, ensures evaluations are never blocked
	policies atomic.Pointer[PolicyMap]
}

// Construct new PolicyStore, empty
func NewPolicyStore() *PolicyStore {
	ps := &PolicyStore{}
	emptyMap := make(PolicyMap)
	ps.policies.Store(&emptyMap)
	return ps
}

// Implement PolicyProvider interface
func (store *PolicyStore) ListActivePolicies(ctx context.Context) ([]Policy, error) {
	// Lock Free Read, load policy pointer snapshot
	currentMapPtr := store.policies.Load()
	currentMap := *currentMapPtr

	policies := make([]Policy, 0, len(currentMap))

	for _, p := range currentMap {
		policies = append(policies, p)
	}

	return policies, nil
}

// UpsertPolicy add or update a policy atomically
func (store *PolicyStore) UpsertPolicy(p Policy) {
	// for loop to retry write.
	for {
		// grab current map
		currentMapPtr := store.policies.Load()
		currentMap := *currentMapPtr

		// create copy
		newMap := make(PolicyMap, len(currentMap)+1)
		maps.Copy(newMap, currentMap)
		newMap[p.ID] = p

		// atomically swap, if we fail loop will restart for another try
		if store.policies.CompareAndSwap(currentMapPtr, &newMap) {
			break
		}
	}
}

// DeletePolicy removes policy atomically
func (store *PolicyStore) DeletePolicy(id string) {
	// for loop to retry write.
	for {
		// grab current map
		currentMapPtr := store.policies.Load()
		currentMap := *currentMapPtr

		// if not present just return
		if _, exists := currentMap[id]; !exists {
			return
		}

		// create copy, with policy to be removed missing.
		newMap := make(PolicyMap, len(currentMap)-1)
		for k, v := range currentMap {
			if k != id {
				newMap[k] = v
			}
		}

		// atomically swap, if we fail loop will restart for another try
		if store.policies.CompareAndSwap(currentMapPtr, &newMap) {
			break
		}
	}
}
