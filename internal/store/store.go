package store

import (
	"context"
	"maps"
	"sync/atomic"
)

// PolicyMap type alias for underlying map
type PolicyMap map[string]Policy

// PolicySnapshot is an immutable view of the active allow and deny tables at
// the instant it was captured. The engine evaluates the deny table first and
// short-circuits on a match, so a single snapshot fixes deny-overrides
// semantics across both tables.
type PolicySnapshot struct {
	Allow []Policy
	Deny  []Policy
}

// PolicyStore manages the in-memory cache of ABAC rules, uses lock-free atomic
// pointers. Allow and deny policies live in separate tables so the engine can
// apply deny-overrides without scanning a combined set.
type PolicyStore struct {
	// atomic pointers to a PolicyMap each, ensures evaluations are never blocked
	allow atomic.Pointer[PolicyMap]
	deny  atomic.Pointer[PolicyMap]
}

// Construct new PolicyStore, empty
func NewPolicyStore() *PolicyStore {
	ps := &PolicyStore{}
	emptyAllow := make(PolicyMap)
	emptyDeny := make(PolicyMap)
	ps.allow.Store(&emptyAllow)
	ps.deny.Store(&emptyDeny)
	return ps
}

// Implement PolicyProvider interface
func (store *PolicyStore) ListActivePolicies(ctx context.Context) (PolicySnapshot, error) {
	// Lock Free Read, load both table snapshots
	allowMap := *store.allow.Load()
	denyMap := *store.deny.Load()

	snapshot := PolicySnapshot{
		Allow: make([]Policy, 0, len(allowMap)),
		Deny:  make([]Policy, 0, len(denyMap)),
	}

	for _, p := range allowMap {
		snapshot.Allow = append(snapshot.Allow, p)
	}
	for _, p := range denyMap {
		snapshot.Deny = append(snapshot.Deny, p)
	}

	return snapshot, nil
}

// UpsertPolicy add or update a policy atomically. Only policies whose Access is
// exactly AccessAllow land in the allow table; everything else (including
// unknown/garbage access modes) routes to the deny table so an unrecognised
// mode can never accidentally grant access.
//
// When a policy's access mode changes (ALLOW<->DENY) the stale entry must be
// evicted from the opposite table, otherwise the ID would exist in both. We
// remove from the opposite table first, then insert into the target table.
// Under deny-overrides every interleaving of those two independent atomic
// operations is fail-safe: while the ID is absent from both tables the request
// falls through to default deny, and while it is present in both the deny table
// is evaluated first and wins.
//
// Note: two goroutines upserting the same ID with conflicting access modes can
// still leave the ID in both tables (each removes from one and inserts into the
// other, and both inserts survive). Decisions remain fail-safe (deny wins),
// but the "one ID -> one entry" invariant is violated. This is inherent to two
// independent atomics; policy-stream updates are effectively single-writer per
// ID in practice.
func (store *PolicyStore) UpsertPolicy(p Policy) {
	if p.Access == AccessAllow {
		store.removeFrom(&store.deny, p.ID)
		store.upsertInto(&store.allow, p)
	} else {
		store.removeFrom(&store.allow, p.ID)
		store.upsertInto(&store.deny, p)
	}
}

// upsertInto add or update a policy in the targeted table atomically
func (store *PolicyStore) upsertInto(target *atomic.Pointer[PolicyMap], p Policy) {
	for {
		currentMapPtr := target.Load()
		currentMap := *currentMapPtr

		newMap := make(PolicyMap, len(currentMap)+1)
		maps.Copy(newMap, currentMap)
		newMap[p.ID] = p

		if target.CompareAndSwap(currentMapPtr, &newMap) {
			break
		}
	}
}

// DeletePolicy removes policy atomically from whichever table holds it
func (store *PolicyStore) DeletePolicy(id string) {
	store.removeFrom(&store.allow, id)
	store.removeFrom(&store.deny, id)
}

// removeFrom deletes an id from the targeted table atomically
func (store *PolicyStore) removeFrom(target *atomic.Pointer[PolicyMap], id string) {
	for {
		currentMapPtr := target.Load()
		currentMap := *currentMapPtr

		if _, exists := currentMap[id]; !exists {
			return
		}

		newMap := make(PolicyMap, len(currentMap)-1)
		for k, v := range currentMap {
			if k != id {
				newMap[k] = v
			}
		}

		if target.CompareAndSwap(currentMapPtr, &newMap) {
			break
		}
	}
}
