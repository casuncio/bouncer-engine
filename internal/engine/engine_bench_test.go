package engine

import (
	"context"
	"testing"

	"github.com/casuncio/bouncer-engine/internal/store"
)

// Create Mock Store for benchmark
func createMockStoreB(b *testing.B, policies []store.Policy) *mockStore {
	b.Helper()

	ms := &mockStore{}
	for i := range policies {
		if err := policies[i].Compile(); err != nil {
			b.Fatalf("Error compiling policy %s: %v", policies[i].ID, err)
		}
		if policies[i].Access == store.AccessAllow {
			ms.allow = append(ms.allow, policies[i])
		} else {
			ms.deny = append(ms.deny, policies[i])
		}
	}

	return ms
}

// BenchmarkEngine_Evaluate simulates a high-throughput access check.
func BenchmarkEngine_Evaluate(b *testing.B) {

	engine := New(createMockStoreB(b, []store.Policy{
		{
			ID:     "pol-bench-all-ops",
			Access: store.AccessAllow,
			Target: store.Target{
				ResourceType: "customer-database",
				Action:       "READ",
			},
			Conditions: []store.Condition{
				{Attribute: "principal.role", Operator: "EQUALS", Value: []string{"admin"}},
				{Attribute: "resource.tags", Operator: "CONTAINS_ALL", Value: []string{"sensitive", "production"}},
				{Attribute: "resource.classifications", Operator: "CONTAINS_ANY", Value: []string{"confidential", "restricted"}},
				{Attribute: "environment.ip_address", Operator: "IN_CIDR", Value: []string{"10.50.0.0/16"}},
				{Attribute: "environment.timestamp", Operator: "BETWEEN", Value: []string{"1786924800", "1786932000"}},
				{Attribute: "principal.email", Operator: "REGEX", Value: []string{`^[a-z]+\@example\.com$`}},
			},
		}}))

	req := &EvaluationRequest{
		PrincipalID:  "usr-88912a",
		ResourceType: "customer-database",
		ResourceID:   "db-prod-us-east",
		Action:       "READ",
		PrincipalAttributes: map[string][]string{
			"role":  {"admin"},
			"email": {"alice@example.com"},
		},
		ResourceAttributes: map[string][]string{
			"tags":            {"sensitive", "production", "us-east"},
			"classifications": {"confidential", "internal"},
		},
		EnvironmentAttributes: map[string][]string{
			"ip_address": {"10.50.14.22"},
			"timestamp":  {"1786928000"},
		},
	}

	ctx := context.Background()
	b.ReportAllocs()

	for b.Loop() {
		_, err := engine.CheckAccess(ctx, req)
		if err != nil {
			b.Fatalf("Unexpected error during evaluation: %v", err)
		}
	}
}

func BenchmarkOperator_EQUALS(b *testing.B) {
	engine := New(&mockStore{
		allow: []store.Policy{
			{
				ID:     "pol-equals",
				Access: store.AccessAllow,
				Target: store.Target{ResourceType: "doc", Action: "READ"},
				Conditions: []store.Condition{
					{Attribute: "principal.role", Operator: "EQUALS", Value: []string{"admin"}},
				},
			},
		},
	})
	req := &EvaluationRequest{
		PrincipalID:  "usr-1",
		ResourceType: "doc",
		Action:       "READ",
		PrincipalAttributes: map[string][]string{
			"role": {"admin"},
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := engine.CheckAccess(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOperator_CONTAINS_ALL(b *testing.B) {
	engine := New(&mockStore{
		allow: []store.Policy{
			{
				ID:     "pol-contains-all",
				Access: store.AccessAllow,
				Target: store.Target{ResourceType: "doc", Action: "READ"},
				Conditions: []store.Condition{
					{Attribute: "principal.roles", Operator: "CONTAINS_ALL", Value: []string{"editor", "reviewer"}},
				},
			},
		},
	})
	req := &EvaluationRequest{
		PrincipalID:  "usr-1",
		ResourceType: "doc",
		Action:       "READ",
		PrincipalAttributes: map[string][]string{
			"roles": {"editor", "reviewer", "viewer"},
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := engine.CheckAccess(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOperator_CONTAINS_ANY(b *testing.B) {
	engine := New(&mockStore{
		allow: []store.Policy{
			{
				ID:     "pol-contains-any",
				Access: store.AccessAllow,
				Target: store.Target{ResourceType: "doc", Action: "READ"},
				Conditions: []store.Condition{
					{Attribute: "principal.roles", Operator: "CONTAINS_ANY", Value: []string{"admin", "superadmin"}},
				},
			},
		},
	})
	req := &EvaluationRequest{
		PrincipalID:  "usr-1",
		ResourceType: "doc",
		Action:       "READ",
		PrincipalAttributes: map[string][]string{
			"roles": {"admin"},
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := engine.CheckAccess(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOperator_IN_CIDR(b *testing.B) {
	engine := New(&mockStore{
		allow: []store.Policy{
			{
				ID:     "pol-cidr",
				Access: store.AccessAllow,
				Target: store.Target{ResourceType: "doc", Action: "READ"},
				Conditions: []store.Condition{
					{Attribute: "environment.ip_address", Operator: "IN_CIDR", Value: []string{"10.50.0.0/16"}},
				},
			},
		},
	})
	req := &EvaluationRequest{
		PrincipalID:  "usr-1",
		ResourceType: "doc",
		Action:       "READ",
		EnvironmentAttributes: map[string][]string{
			"ip_address": {"10.50.14.22"},
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := engine.CheckAccess(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOperator_BETWEEN(b *testing.B) {
	engine := New(&mockStore{
		allow: []store.Policy{
			{
				ID:     "pol-between",
				Access: store.AccessAllow,
				Target: store.Target{ResourceType: "doc", Action: "READ"},
				Conditions: []store.Condition{
					{Attribute: "environment.timestamp", Operator: "BETWEEN", Value: []string{"1786924800", "1786932000"}},
				},
			},
		},
	})
	req := &EvaluationRequest{
		PrincipalID:  "usr-1",
		ResourceType: "doc",
		Action:       "READ",
		EnvironmentAttributes: map[string][]string{
			"timestamp": {"1786928000"},
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := engine.CheckAccess(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOperator_REGEX(b *testing.B) {
	policies := []store.Policy{
		{
			ID:     "pol-regex",
			Access: store.AccessAllow,
			Target: store.Target{ResourceType: "doc", Action: "READ"},
			Conditions: []store.Condition{
				{Attribute: "principal.email", Operator: "REGEX", Value: []string{`^[a-z]+\@example\.com$`}},
			},
		},
	}

	engine := New(createMockStoreB(b, policies))
	req := &EvaluationRequest{
		PrincipalID:  "usr-1",
		ResourceType: "doc",
		Action:       "READ",
		PrincipalAttributes: map[string][]string{
			"email": {"alice@example.com"},
		},
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := engine.CheckAccess(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}
