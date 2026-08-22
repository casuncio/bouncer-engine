package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func countPolicies(t *testing.T, s *PolicyStore) int {
	t.Helper()
	snap, err := s.ListActivePolicies(context.Background())
	if err != nil {
		t.Fatalf("ListActivePolicies error: %v", err)
	}
	return len(snap.Allow) + len(snap.Deny)
}

func TestPolicyStore_ConcurrentReadWrite(t *testing.T) {
	store := NewPolicyStore()

	// Seed an initial policy
	initialPolicy := Policy{
		ID:          "pol-initial",
		Description: "Initial Policy",
		Access:      AccessAllow,
	}
	store.UpsertPolicy(initialPolicy)

	var wg sync.WaitGroup
	workers := 50
	iterations := 100

	// Spawn concurrent writers
	for i := range workers {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				p := Policy{
					ID:     fmt.Sprintf("pol-worker-%d-iter-%d", workerID, j),
					Access: AccessAllow,
				}
				store.UpsertPolicy(p)
			}
		}(i)
	}

	// Spawn concurrent readers
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				snap, err := store.ListActivePolicies(context.Background())
				if err != nil {
					t.Errorf("Unexpected error during read: %v", err)
				}
				// store may be momentarily mid-transition during concurrent writes, just verify no panic/corruption
				_ = snap
			}
		}()
	}

	wg.Wait()

	// Verify final state
	// Initial (1) + (workers * iterations)
	expectedCount := 1 + (workers * iterations)
	if got := countPolicies(t, store); got != expectedCount {
		t.Errorf("Expected %d policies, got %d", expectedCount, got)
	}
}

func TestPolicyStore_DeletePolicy(t *testing.T) {
	t.Run("delete_existing", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-1", Access: AccessAllow})
		store.DeletePolicy("pol-1")

		if got := countPolicies(t, store); got != 0 {
			t.Errorf("Expected 0 policies, got %d", got)
		}
	})

	t.Run("delete_nonexistent", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-1", Access: AccessAllow})

		store.DeletePolicy("pol-does-not-exist")

		if got := countPolicies(t, store); got != 1 {
			t.Errorf("Expected 1 policy, got %d", got)
		}
	})

	t.Run("delete_from_empty", func(t *testing.T) {
		store := NewPolicyStore()

		store.DeletePolicy("pol-anything")

		if got := countPolicies(t, store); got != 0 {
			t.Errorf("Expected 0 policies, got %d", got)
		}
	})

	t.Run("delete_one_of_many", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-a", Access: AccessAllow})
		store.UpsertPolicy(Policy{ID: "pol-b", Access: AccessDeny})
		store.UpsertPolicy(Policy{ID: "pol-c", Access: AccessAllow})

		store.DeletePolicy("pol-b")

		snap, _ := store.ListActivePolicies(context.Background())
		if len(snap.Allow)+len(snap.Deny) != 2 {
			t.Fatalf("Expected 2 policies, got %d", len(snap.Allow)+len(snap.Deny))
		}

		ids := map[string]bool{}
		for _, p := range snap.Allow {
			ids[p.ID] = true
		}
		for _, p := range snap.Deny {
			ids[p.ID] = true
		}
		if !ids["pol-a"] || !ids["pol-c"] {
			t.Errorf("Expected pol-a and pol-c to remain, got %v", ids)
		}
		if ids["pol-b"] {
			t.Error("pol-b should have been deleted")
		}
	})

	t.Run("delete_last_remaining", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-only", Access: AccessAllow})

		store.DeletePolicy("pol-only")

		if got := countPolicies(t, store); got != 0 {
			t.Errorf("Expected 0 policies, got %d", got)
		}
	})

	t.Run("upsert_after_delete", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-recycle", Access: AccessAllow})
		store.DeletePolicy("pol-recycle")

		store.UpsertPolicy(Policy{ID: "pol-recycle", Access: AccessDeny})

		snap, _ := store.ListActivePolicies(context.Background())
		if len(snap.Allow)+len(snap.Deny) != 1 {
			t.Fatalf("Expected 1 policy, got %d", len(snap.Allow)+len(snap.Deny))
		}
		if len(snap.Deny) != 1 || snap.Deny[0].Access != AccessDeny {
			t.Errorf("Expected AccessDeny in deny table after re-upsert")
		}
	})
}

func TestPolicyStore_UpsertPolicy(t *testing.T) {
	t.Run("upsert_creates_new_policy", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-new", Access: AccessAllow})

		snap, _ := store.ListActivePolicies(context.Background())
		if len(snap.Allow) != 1 {
			t.Fatalf("Expected 1 allow policy, got %d", len(snap.Allow))
		}
		if snap.Allow[0].ID != "pol-new" {
			t.Errorf("Expected ID pol-new, got %s", snap.Allow[0].ID)
		}
	})

	t.Run("upsert_updates_existing_policy", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-update", Access: AccessAllow, Description: "v1"})
		store.UpsertPolicy(Policy{ID: "pol-update", Access: AccessDeny, Description: "v2"})

		snap, _ := store.ListActivePolicies(context.Background())
		if len(snap.Allow)+len(snap.Deny) != 1 {
			t.Fatalf("Expected 1 policy, got %d", len(snap.Allow)+len(snap.Deny))
		}
		if len(snap.Allow) != 0 {
			t.Errorf("Expected stale allow entry to be evicted, got %d in allow table", len(snap.Allow))
		}
		if len(snap.Deny) != 1 || snap.Deny[0].Access != AccessDeny {
			t.Errorf("Expected AccessDeny in deny table")
		}
		if snap.Deny[0].Description != "v2" {
			t.Errorf("Expected description v2, got %s", snap.Deny[0].Description)
		}
	})

	t.Run("allow_routes_to_allow_table", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-a", Access: AccessAllow})

		snap, _ := store.ListActivePolicies(context.Background())
		if len(snap.Allow) != 1 || len(snap.Deny) != 0 {
			t.Fatalf("Expected 1 allow / 0 deny, got %d/%d", len(snap.Allow), len(snap.Deny))
		}
	})

	t.Run("deny_routes_to_deny_table", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-d", Access: AccessDeny})

		snap, _ := store.ListActivePolicies(context.Background())
		if len(snap.Deny) != 1 || len(snap.Allow) != 0 {
			t.Fatalf("Expected 0 allow / 1 deny, got %d/%d", len(snap.Allow), len(snap.Deny))
		}
	})

	t.Run("garbage_access_routes_to_deny_table", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-g", Access: Access("AUDIT")})

		snap, _ := store.ListActivePolicies(context.Background())
		if len(snap.Deny) != 1 || len(snap.Allow) != 0 {
			t.Fatalf("Expected unknown access mode to land in deny table (fail-closed), got %d/%d", len(snap.Allow), len(snap.Deny))
		}
	})

	t.Run("access_mode_transition_moves_between_tables", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-flip", Access: AccessAllow})
		store.UpsertPolicy(Policy{ID: "pol-flip", Access: AccessDeny})

		snap, _ := store.ListActivePolicies(context.Background())
		if len(snap.Allow)+len(snap.Deny) != 1 {
			t.Fatalf("Expected exactly 1 policy after transition, got %d", len(snap.Allow)+len(snap.Deny))
		}
		if len(snap.Allow) != 0 || len(snap.Deny) != 1 {
			t.Fatalf("Expected policy moved to deny table, got allow=%d deny=%d", len(snap.Allow), len(snap.Deny))
		}

		store.UpsertPolicy(Policy{ID: "pol-flip", Access: AccessAllow})
		snap, _ = store.ListActivePolicies(context.Background())
		if len(snap.Allow)+len(snap.Deny) != 1 {
			t.Fatalf("Expected exactly 1 policy after flip back, got %d", len(snap.Allow)+len(snap.Deny))
		}
		if len(snap.Allow) != 1 || len(snap.Deny) != 0 {
			t.Fatalf("Expected policy moved back to allow table, got allow=%d deny=%d", len(snap.Allow), len(snap.Deny))
		}
	})
}

func TestPolicyStore_DeletePolicy_Concurrent(t *testing.T) {
	t.Run("concurrent_delete_different_keys", func(t *testing.T) {
		store := NewPolicyStore()

		workers := 50
		for i := range workers {
			store.UpsertPolicy(Policy{
				ID:     fmt.Sprintf("pol-del-%d", i),
				Access: AccessAllow,
			})
		}

		var wg sync.WaitGroup
		for i := range workers {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				store.DeletePolicy(fmt.Sprintf("pol-del-%d", id))
			}(i)
		}
		wg.Wait()

		if got := countPolicies(t, store); got != 0 {
			t.Errorf("Expected 0 policies after deleting all, got %d", got)
		}
	})

	t.Run("concurrent_delete_while_reading", func(t *testing.T) {
		store := NewPolicyStore()

		for i := range 50 {
			store.UpsertPolicy(Policy{
				ID:     fmt.Sprintf("pol-%d", i),
				Access: AccessAllow,
			})
		}

		var wg sync.WaitGroup

		// deleters
		for i := range 50 {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				store.DeletePolicy(fmt.Sprintf("pol-%d", id))
			}(i)
		}

		// readers
		for range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					snap, err := store.ListActivePolicies(context.Background())
					if err != nil {
						t.Errorf("Unexpected error during read: %v", err)
					}
					// store may be empty during concurrent deletes, just verify no panic/corruption
					_ = snap
				}
			}()
		}

		wg.Wait()
	})

	t.Run("concurrent_delete_and_upsert_same_key", func(t *testing.T) {
		store := NewPolicyStore()

		key := "pol-contentious"

		var wg sync.WaitGroup

		// upserters
		for range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				store.UpsertPolicy(Policy{ID: key, Access: AccessAllow})
			}()
		}

		// deleters
		for range 50 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				store.DeletePolicy(key)
			}()
		}

		wg.Wait()

		snap, _ := store.ListActivePolicies(context.Background())
		total := len(snap.Allow) + len(snap.Deny)

		// Final state: key either exists (1) or doesn't (0), no panics or corruption
		if total > 1 {
			t.Errorf("Expected at most 1 policy, got %d", total)
		}
	})

	t.Run("concurrent_delete_same_key", func(t *testing.T) {
		store := NewPolicyStore()
		store.UpsertPolicy(Policy{ID: "pol-shared", Access: AccessAllow})

		workers := 50
		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				store.DeletePolicy("pol-shared")
			}()
		}
		wg.Wait()

		if got := countPolicies(t, store); got != 0 {
			t.Errorf("Expected 0 policies after concurrent delete of same key, got %d", got)
		}
	})
}

func BenchmarkUpsertPolicy(b *testing.B) {
	store := NewPolicyStore()

	b.Run("insert", func(b *testing.B) {
		for b.Loop() {
			store.UpsertPolicy(Policy{
				ID:     fmt.Sprintf("pol-bench-%d", b.N),
				Access: AccessAllow,
			})
		}
	})

	b.Run("update", func(b *testing.B) {
		for b.Loop() {
			store.UpsertPolicy(Policy{
				ID:     "pol-static",
				Access: AccessAllow,
			})
		}
	})
}

func BenchmarkListActivePolicies(b *testing.B) {
	store := NewPolicyStore()
	for i := range 1000 {
		store.UpsertPolicy(Policy{
			ID:     fmt.Sprintf("pol-%d", i),
			Access: AccessAllow,
		})
	}

	b.Run("1000_policies", func(b *testing.B) {
		for b.Loop() {
			store.ListActivePolicies(context.Background())
		}
	})
}
