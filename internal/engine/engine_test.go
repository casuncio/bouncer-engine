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

func TestEngine_equals(t *testing.T) {
	// Setup our mock store with one data protection policy for Equals
	mockStore := &MockStore{
		Policies: []store.Policy{
			{
				ID:          "perf-metrics-001",
				Description: "Anyone can read performace metrics, while on internal VPN",
				Access:      store.AccessAllow,
				Target: store.Target{
					ResourceType: "endpoint-metrics-log",
					Action:       "READ",
				},
				Conditions: []store.Condition{
					{
						Attribute: "environment.network_zone",
						Operator:  "EQUALS",
						Value:     []string{"internal-vpn"},
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
			name: "Basic Equals Test",
			request: EvaluationRequest{
				ResourceType: "endpoint-metrics-log",
				Action:       "READ",
				PrincipalAttributes: map[string]string{
					"roles": "DevOps",
				},
				EnvironmentAttributes: map[string]string{
					"network_zone": "internal-vpn",
				},
			},
			expectAllowed: true,
			expectPolicy:  "perf-metrics-001",
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
// 					// 	Operator:  "CONTAINS",
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
