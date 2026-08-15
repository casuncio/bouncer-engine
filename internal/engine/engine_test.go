package engine

import (
	"context"
	"testing"

	"github.com/casuncio/bouncer-engine/internal/store"
)

// MockStore implements PolicyProvider for testing.
type MockStore struct {
	Policies []store.Policy
}

func (m *MockStore) ListActivePolicies(ctx context.Context) ([]store.Policy, error) {
	return m.Policies, nil
}

type AccessTest struct {
	name          string
	request       EvaluationRequest
	expectAllowed bool
	expectPolicy  string
}

func runTests(t *testing.T, tests []AccessTest, authzEngine *Engine) {

	// Execute tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := authzEngine.CheckAccess(context.Background(), &tt.request)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if resp.Allowed != tt.expectAllowed {
				t.Errorf("Expected Allowed to be %v, got %v", tt.expectAllowed, resp.Allowed)
			}

			if resp.MatchedPolicyID != tt.expectPolicy {
				t.Errorf("Expected PolicyID '%s', got '%s'", tt.expectPolicy, resp.MatchedPolicyID)
			}
		})
	}
}

func TestEngine_Basic(t *testing.T) {
	// Setup our mock store with one data protection policy for Equals
	mockStore := &MockStore{
		Policies: []store.Policy{
			{
				ID:          "basic-equals",
				Description: "Basic Policy with just one condition for equals",
				Access:      store.AccessAllow,
				Target: store.Target{
					ResourceType: "endpoint-metrics-log",
					Action:       "READ",
				},
				Conditions: []store.Condition{
					{
						Attribute: "environment.network_zone",
						Operator:  "EQUALS",
						Value:     []string{"internal-data", "backup-mgmt"},
					},
				},
			},
			{
				ID:          "basic-contains-all",
				Description: "Basic Policy with just one condition for contains all",
				Access:      store.AccessAllow,
				Target: store.Target{
					ResourceType: "audit-log",
					Action:       "READ",
				},
				Conditions: []store.Condition{
					{
						Attribute: "principal.roles",
						Operator:  "CONTAINS_ALL",
						Value:     []string{"Admin"},
					},
				},
			},
			{
				ID:          "basic-contains-all-multi",
				Description: "Basic Policy with just one condition for contains all multi value",
				Access:      store.AccessAllow,
				Target: store.Target{
					ResourceType: "backup-database",
					Action:       "READ",
				},
				Conditions: []store.Condition{
					{
						Attribute: "resource.network_zone",
						Operator:  "CONTAINS_ALL",
						Value:     []string{"internal-data", "backup-mgmt"},
					},
				},
			},
			{
				ID:          "basic-contains-any",
				Description: "Basic Policy with just one condition for contains any",
				Access:      store.AccessAllow,
				Target: store.Target{
					ResourceType: "internal-database",
					Action:       "READ",
				},
				Conditions: []store.Condition{
					{
						Attribute: "resource.network_zone",
						Operator:  "CONTAINS_ANY",
						Value:     []string{"internal-data", "backup-mgmt"},
					},
				},
			},
		},
	}

	// Initialize the engine with the mock store
	authzEngine := New(mockStore)

	// Test case
	tests := []AccessTest{
		{
			name: "Basic Equals Test 1",
			request: EvaluationRequest{
				ResourceType: "endpoint-metrics-log",
				Action:       "READ",
				PrincipalAttributes: map[string][]string{
					"roles": {"DevOps", "Admin"},
				},
				EnvironmentAttributes: map[string][]string{
					"network_zone": {"internal-data", "backup-mgmt"},
				},
			},
			expectAllowed: true,
			expectPolicy:  "basic-equals",
		},
		{
			name: "Basic Equals Test 2",
			request: EvaluationRequest{
				ResourceType: "endpoint-metrics-log",
				Action:       "READ",
				PrincipalAttributes: map[string][]string{
					"roles": {"DevOps", "Admin"},
				},
				EnvironmentAttributes: map[string][]string{
					"network_zone": {"backup-mgmt", "internal-data"},
				},
			},
			expectAllowed: true,
			expectPolicy:  "basic-equals",
		},
		{
			name: "Basic CONTAINS_ALL Test",
			request: EvaluationRequest{
				ResourceType: "audit-log",
				Action:       "READ",
				PrincipalAttributes: map[string][]string{
					"roles": {"DevOps", "Admin"},
				},
				ResourceAttributes: map[string][]string{
					"network_zone": {"internal-vpn"},
				},
			},
			expectAllowed: true,
			expectPolicy:  "basic-contains-all",
		},
		{
			name: "Basic CONTAINS_ALL Multi Test",
			request: EvaluationRequest{
				ResourceType: "backup-database",
				Action:       "READ",
				PrincipalAttributes: map[string][]string{
					"roles": {"DevOps", "Admin"},
				},
				ResourceAttributes: map[string][]string{
					"network_zone": {"internal-data", "backup-mgmt", "internal-vpn"},
				},
			},
			expectAllowed: true,
			expectPolicy:  "basic-contains-all-multi",
		},
		{
			name: "Basic CONTAINS_ANY Test",
			request: EvaluationRequest{
				ResourceType: "internal-database",
				Action:       "READ",
				PrincipalAttributes: map[string][]string{
					"roles": {"DevOps", "Admin"},
				},
				ResourceAttributes: map[string][]string{
					"network_zone": {"internal-data"},
				},
			},
			expectAllowed: true,
			expectPolicy:  "basic-contains-any",
		},
	}

	runTests(t, tests, authzEngine)

}

// func TestEngine_CheckAccess(t *testing.T) {
// 	// Setup our mock store with one strict data protection policy
// 	mockStore := &MockStore{
// 		Policies: []store.Policy{
// 			{
// 				ID:          "pol-threat-001",
// 				Description: "Security Admins can read endpoint threat logs",
// 				Access:      store.AccessAllow,
// 				Target: store.Target{
// 					ResourceType: "endpoint-threat-log",
// 					Action:       "READ",
// 				},
// 				Conditions: []store.Condition{
// 					// {
// 					// 	Attribute: "principal.roles",
// 					// 	Operator:  "CONTAINS_ALL",
// 					// 	Value:     []string{"SecurityAdmin"},
// 					// },
// 					{
// 						Attribute: "environment.network_zone",
// 						Operator:  "EQUALS",
// 						Value:     []string{"internal-vpn"},
// 					},
// 				},
// 			},
// 		},
// 	}

// 	// Initialize the engine with the mock store
// 	authzEngine := New(mockStore)

// 	// Define our test cases
// 	tests := []AccessTest{
// 		{
// 			name: "Authorized Request - Meets all conditions",
// 			request: EvaluationRequest{
// 				ResourceType: "endpoint-threat-log",
// 				Action:       "READ",
// 				PrincipalAttributes: map[string]string{
// 					"roles": "User,SecurityAdmin,DevOps",
// 				},
// 				EnvironmentAttributes: map[string]string{
// 					"network_zone": "internal-vpn",
// 				},
// 			},
// 			expectAllowed: true,
// 			expectPolicy:  "pol-threat-001",
// 		},
// 		{
// 			name: "Unauthorized Request - Wrong network zone",
// 			request: EvaluationRequest{
// 				ResourceType: "endpoint-threat-log",
// 				Action:       "READ",
// 				PrincipalAttributes: map[string]string{
// 					"roles": "SecurityAdmin",
// 				},
// 				EnvironmentAttributes: map[string]string{
// 					"network_zone": "public-internet", // Fails condition
// 				},
// 			},
// 			expectAllowed: false,
// 			expectPolicy:  "",
// 		},
// 		{
// 			name: "Unauthorized Request - Missing Role",
// 			request: EvaluationRequest{
// 				ResourceType: "endpoint-threat-log",
// 				Action:       "READ",
// 				PrincipalAttributes: map[string]string{
// 					"roles": "DevOps", // Missing SecurityAdmin
// 				},
// 				EnvironmentAttributes: map[string]string{
// 					"network_zone": "internal-vpn",
// 				},
// 			},
// 			expectAllowed: false,
// 			expectPolicy:  "",
// 		},
// 	}

// 	runTests(t, tests, authzEngine)

// }
