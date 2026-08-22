package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/casuncio/bouncer-engine/internal/store"
)

// mockStore implements PolicyProvider for testing. Allow and deny policies are
// partitioned once at construction so ListActivePolicies mirrors the real
// PolicyStore with zero per-call work.
type mockStore struct {
	allow []store.Policy
	deny  []store.Policy
}

// Create Mock Store for unittesting
func createMockStore(t *testing.T, policies []store.Policy) *mockStore {
	t.Helper()

	ms := &mockStore{}
	for i := range policies {
		if err := policies[i].Compile(); err != nil {
			t.Fatalf("Error compiling policy %s: %v", policies[i].ID, err)
		}
		if policies[i].Access == store.AccessAllow {
			ms.allow = append(ms.allow, policies[i])
		} else {
			ms.deny = append(ms.deny, policies[i])
		}
	}

	return ms
}

func (m *mockStore) ListActivePolicies(ctx context.Context) (store.PolicySnapshot, error) {
	return store.PolicySnapshot{Allow: m.allow, Deny: m.deny}, nil
}

// checkFunc is an injectable evaluation function so a table of cases can be
// run against any engine implementation (e.g. middleware wrapping CheckAccess).
type checkFunc func(ctx context.Context, req *EvaluationRequest) (EvaluationResponse, error)

// testCase describes a single authorization scenario. The json tags let the
// same struct be fed from testdata files; Check is never decoded.
type testCase struct {
	Name         string            `json:"name"`
	Policies     []store.Policy    `json:"policies"`
	Request      EvaluationRequest `json:"request"`
	WantAllowed  bool              `json:"want_allowed"`
	WantPolicyID string            `json:"want_policy_id"`
	WantErr      bool              `json:"want_err,omitempty"`
	WantReason   string            `json:"want_reason,omitempty"`
	Check        checkFunc         `json:"-"`
}

// runTestCases executes each case as a subtest, spinning up a fresh engine
// per case so policies never leak between scenarios.
func runTestCases(t *testing.T, cases []testCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			runTestCase(t, tc)
		})
	}
}

// runTestCase runs a single test case against a fresh engine.
func runTestCase(t *testing.T, tc testCase) {
	t.Helper()

	check := tc.Check
	if check == nil {
		engine := New(createMockStore(t, tc.Policies))
		check = engine.CheckAccess
	}

	resp, err := check(context.Background(), &tc.Request)
	if tc.WantErr {
		if err == nil {
			t.Fatalf("expected an error, got nil")
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Allowed != tc.WantAllowed {
		t.Errorf("Allowed = %v, want %v", resp.Allowed, tc.WantAllowed)
	}
	if resp.MatchedPolicyID != tc.WantPolicyID {
		t.Errorf("MatchedPolicyID = %q, want %q", resp.MatchedPolicyID, tc.WantPolicyID)
	}
	if tc.WantReason != "" && resp.Reason != tc.WantReason {
		t.Errorf("Reason = %q, want %q", resp.Reason, tc.WantReason)
	}
}

// loadTestCases reads a JSON file of test cases from disk.
func loadTestCases(t *testing.T, path string) []testCase {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}

	var cases []testCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}

	for i := range cases {
		for j := range cases[i].Policies {
			policy := cases[i].Policies[j]
			if err := policy.Compile(); err != nil {
				t.Fatal(err)
			}
		}
	}

	return cases
}

// loadAllTestCases loads every JSON scenario file under testdata.
func loadAllTestCases(t *testing.T) []testCase {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatalf("failed to list testdata files: %v", err)
	}

	var cases []testCase
	for _, path := range paths {
		cases = append(cases, loadTestCases(t, path)...)
	}
	return cases
}

// TestEngine_Test feeds the engine with scenario files under testdata.
func TestEngine_Test(t *testing.T) {
	runTestCases(t, loadAllTestCases(t))
}
