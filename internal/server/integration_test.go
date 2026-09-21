package server_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/casuncio/bouncer-engine/internal/audit"
	"github.com/casuncio/bouncer-engine/internal/engine"
	"github.com/casuncio/bouncer-engine/internal/server"
	"github.com/casuncio/bouncer-engine/internal/store"
	"github.com/casuncio/bouncer-engine/internal/subscriber"
	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type testEnv struct {
	client pb.AuthorizationServiceClient
	store  *store.PolicyStore
	redis  *redis.Client
}

func setupTestServer(t *testing.T) *testEnv {
	t.Helper()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	policyStore := store.NewPolicyStore()
	abacEngine := engine.New(policyStore)
	auditLogger := audit.NewAuditLogger(1000)
	auditLogger.Start(2)
	t.Cleanup(auditLogger.Stop)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go subscriber.NewPolicyUpdateSubscriber(subscriber.StreamKey, rdb, policyStore).Start(ctx)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthorizationServiceServer(grpcServer, server.NewAuthzServer(abacEngine, auditLogger))
	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(grpcServer.GracefulStop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})

	return &testEnv{
		client: pb.NewAuthorizationServiceClient(conn),
		store:  policyStore,
		redis:  rdb,
	}
}

type policyUpdate struct {
	id      string
	action  string
	json    string
	invalid bool
}

// applyPolicyUpdates publishes the given updates to the Redis stream and waits
// until the subscriber has applied every update that should change the store.
func applyPolicyUpdates(t *testing.T, env *testEnv, updates ...policyUpdate) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type expectation int
	const (
		expectPresent expectation = iota
		expectAbsent
		expectIgnore
	)
	expected := make(map[string]expectation, len(updates))

	for _, update := range updates {
		if err := subscriber.Publish(ctx, env.redis, subscriber.StreamKey, update.action, update.id, update.json); err != nil {
			t.Fatalf("failed to publish policy update %q: %v", update.id, err)
		}
		switch {
		case update.action == subscriber.ActionDelete:
			expected[update.id] = expectAbsent
		case update.invalid:
			if _, seen := expected[update.id]; !seen {
				expected[update.id] = expectIgnore
			}
		default:
			expected[update.id] = expectPresent
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		snap, err := env.store.ListActivePolicies(context.Background())
		if err != nil {
			t.Fatalf("failed to list policies: %v", err)
		}
		ids := make(map[string]struct{}, len(snap.Allow)+len(snap.Deny))
		for _, p := range snap.Allow {
			ids[p.ID] = struct{}{}
		}
		for _, p := range snap.Deny {
			ids[p.ID] = struct{}{}
		}

		ready := true
		for id, want := range expected {
			_, found := ids[id]
			switch want {
			case expectPresent:
				if !found {
					ready = false
				}
			case expectAbsent:
				if found {
					ready = false
				}
			}
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for redis policy updates to apply; store has %d policies", len(ids))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func upsertPolicy(id string, access string, resourceType string, action string, conditions string) policyUpdate {
	return policyUpdate{
		id:     id,
		action: subscriber.ActionUpsert,
		json: `{
			"id": "` + id + `",
			"description": "integration test policy",
			"access": "` + access + `",
			"target": {"resource_type": "` + resourceType + `", "action": "` + action + `"},
			"conditions": ` + conditions + `
		}`,
	}
}

func deletePolicy(id string) policyUpdate {
	return policyUpdate{
		id:     id,
		action: subscriber.ActionDelete,
	}
}

func checkAccess(client pb.AuthorizationServiceClient, principalID string, attrs map[string]*pb.AttributeValues, resourceType string, action string) (*pb.CheckAccessResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return client.CheckAccess(ctx, &pb.CheckAccessRequest{
		PrincipalId:         principalID,
		ResourceType:        resourceType,
		Action:              action,
		PrincipalAttributes: attrs,
	})
}

func TestIntegration_CheckAccess_DefaultDeny(t *testing.T) {
	env := setupTestServer(t)

	resp, err := checkAccess(env.client, "usr-1", map[string]*pb.AttributeValues{
		"role": {Values: []string{"viewer"}},
	}, "document", "READ")
	if err != nil {
		t.Fatalf("unexpected CheckAccess error: %v", err)
	}

	if resp.Allowed {
		t.Fatalf("expected request to be denied by default, got allowed")
	}
	if resp.MatchedPolicyId != "" {
		t.Errorf("expected no matched policy on default deny, got %q", resp.MatchedPolicyId)
	}
	if resp.Reason == "" {
		t.Errorf("expected a non-empty denial reason")
	}
	if resp.EvaluationTimeNs <= 0 {
		t.Errorf("expected evaluation latency to be recorded, got %d", resp.EvaluationTimeNs)
	}
}

func TestIntegration_HotReload_And_ConcurrentAccess(t *testing.T) {
	env := setupTestServer(t)

	applyPolicyUpdates(t, env,
		upsertPolicy("pol-integration-001", "ALLOW", "database", "WRITE",
			`[{"attribute": "principal.role", "operator": "EQUALS", "value": ["admin"]}]`),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	workers := 10
	requestsPerWorker := 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < requestsPerWorker; j++ {
				resp, reqErr := env.client.CheckAccess(ctx, &pb.CheckAccessRequest{
					PrincipalId:         "usr-admin",
					ResourceType:        "database",
					Action:              "WRITE",
					PrincipalAttributes: map[string]*pb.AttributeValues{"role": {Values: []string{"admin"}}},
				})
				if reqErr != nil {
					t.Errorf("worker %d failed request %d: %v", workerID, j, reqErr)
					return
				}
				if !resp.Allowed {
					t.Errorf("expected allowed=true for admin, got false (reason: %s)", resp.Reason)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestIntegration_PolicyDelete_RoundTrip(t *testing.T) {
	env := setupTestServer(t)

	const policyID = "pol-integration-002"

	applyPolicyUpdates(t, env,
		upsertPolicy(policyID, "ALLOW", "document", "READ",
			`[{"attribute": "principal.role", "operator": "EQUALS", "value": ["editor"]}]`),
	)

	resp, err := checkAccess(env.client, "usr-2", map[string]*pb.AttributeValues{
		"role": {Values: []string{"editor"}},
	}, "document", "READ")
	if err != nil {
		t.Fatalf("unexpected CheckAccess error after upsert: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true for editor after upsert, got false (reason: %s)", resp.Reason)
	}
	if resp.MatchedPolicyId != policyID {
		t.Errorf("expected matched policy id %q, got %q", policyID, resp.MatchedPolicyId)
	}

	applyPolicyUpdates(t, env, deletePolicy(policyID))

	resp, err = checkAccess(env.client, "usr-2", map[string]*pb.AttributeValues{
		"role": {Values: []string{"editor"}},
	}, "document", "READ")
	if err != nil {
		t.Fatalf("unexpected CheckAccess error after delete: %v", err)
	}
	if resp.Allowed {
		t.Fatalf("expected allowed=false after policy deletion, got true")
	}
	if resp.MatchedPolicyId != "" {
		t.Errorf("expected empty matched policy id after deletion, got %q", resp.MatchedPolicyId)
	}
}

func TestIntegration_InvalidPolicyJson_ContinuesServing(t *testing.T) {
	env := setupTestServer(t)

	applyPolicyUpdates(t, env,
		policyUpdate{
			id:      "pol-broken-json",
			action:  subscriber.ActionUpsert,
			json:    `{ this is not valid json `,
			invalid: true,
		},
		upsertPolicy("pol-recovery-001", "ALLOW", "document", "WRITE",
			`[{"attribute": "principal.role", "operator": "EQUALS", "value": ["admin"]}]`),
	)

	resp, err := checkAccess(env.client, "usr-admin", map[string]*pb.AttributeValues{
		"role": {Values: []string{"admin"}},
	}, "document", "WRITE")
	if err != nil {
		t.Fatalf("unexpected CheckAccess error after malformed update: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true after recovering from malformed update, got false (reason: %s)", resp.Reason)
	}
	if resp.MatchedPolicyId != "pol-recovery-001" {
		t.Errorf("expected recovery policy %q to match, got %q", "pol-recovery-001", resp.MatchedPolicyId)
	}
}

func TestIntegration_RegexPolicy_EndToEnd(t *testing.T) {
	env := setupTestServer(t)

	applyPolicyUpdates(t, env,
		upsertPolicy("pol-regex-001", "ALLOW", "vault", "UNSEAL",
			`[{"attribute": "principal.account_id", "operator": "REGEX", "value": ["^svc-[a-z]+-prod$"]}]`),
	)

	tests := []struct {
		name      string
		accountID string
		wantAllow bool
	}{
		{name: "matching service account", accountID: "svc-vault-prod", wantAllow: true},
		{name: "non prod service account", accountID: "svc-vault-dev", wantAllow: false},
		{name: "human account", accountID: "usr-1234", wantAllow: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := env.client.CheckAccess(context.Background(), &pb.CheckAccessRequest{
				PrincipalId:         tt.accountID,
				ResourceType:        "vault",
				Action:              "UNSEAL",
				PrincipalAttributes: map[string]*pb.AttributeValues{"account_id": {Values: []string{tt.accountID}}},
			})
			if err != nil {
				t.Fatalf("unexpected CheckAccess error: %v", err)
			}
			if resp.Allowed != tt.wantAllow {
				t.Fatalf("expected allowed=%v for account %q, got %v (reason: %s)",
					tt.wantAllow, tt.accountID, resp.Allowed, resp.Reason)
			}
			if tt.wantAllow && resp.MatchedPolicyId != "pol-regex-001" {
				t.Errorf("expected regex policy %q to match, got %q", "pol-regex-001", resp.MatchedPolicyId)
			}
		})
	}
}

func TestIntegration_DenyPolicy_OverridesAllow(t *testing.T) {
	env := setupTestServer(t)

	// Both a DENY and an ALLOW policy target the same resource/action and both
	// would match the request. Deny-overrides must return denied with the deny
	// policy id, deterministically, regardless of publish order.
	applyPolicyUpdates(t, env,
		upsertPolicy("pol-allow-001", "ALLOW", "document", "WRITE",
			`[{"attribute": "principal.role", "operator": "EQUALS", "value": ["intern"]}]`),
		upsertPolicy("pol-deny-001", "DENY", "document", "WRITE",
			`[{"attribute": "principal.role", "operator": "EQUALS", "value": ["intern"]}]`),
	)

	resp, err := checkAccess(env.client, "usr-intern", map[string]*pb.AttributeValues{
		"role": {Values: []string{"intern"}},
	}, "document", "WRITE")
	if err != nil {
		t.Fatalf("unexpected CheckAccess error: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected denied: explicit DENY must override matching ALLOW")
	}
	if resp.MatchedPolicyId != "pol-deny-001" {
		t.Errorf("expected deny policy %q to win, got %q (reason: %s)", "pol-deny-001", resp.MatchedPolicyId, resp.Reason)
	}
}

// TestIntegration_RedisPublish_ReportsActiveCount guards that publishing
// upserts and deletes on the Redis stream changes the live store count. The
// old StreamPolicyUpdates acknowledgement no longer exists; Count() is the
// in-process equivalent of the Prometheus authz_policy_count gauge.
func TestIntegration_RedisPublish_ReportsActiveCount(t *testing.T) {
	env := setupTestServer(t)

	if got := env.store.Count(); got != 0 {
		t.Fatalf("expected active policy count=0 on fresh store, got %d", got)
	}

	applyPolicyUpdates(t, env,
		upsertPolicy("pol-count-001", "ALLOW", "document", "READ",
			`[{"attribute": "principal.role", "operator": "EQUALS", "value": ["admin"]}]`),
		upsertPolicy("pol-count-002", "DENY", "document", "WRITE",
			`[{"attribute": "principal.role", "operator": "EQUALS", "value": ["intern"]}]`),
		upsertPolicy("pol-count-003", "ALLOW", "vault", "UNSEAL",
			`[{"attribute": "principal.account_id", "operator": "REGEX", "value": ["^svc-.*"]}]`),
	)
	if got := env.store.Count(); got != 3 {
		t.Fatalf("expected active policy count=3 after upserts, got %d", got)
	}

	applyPolicyUpdates(t, env, deletePolicy("pol-count-002"))
	if got := env.store.Count(); got != 2 {
		t.Fatalf("expected active policy count=2 after delete, got %d", got)
	}

	// The reported count must reflect real store state: the surviving allow
	// policy still grants admin READ, and the deleted deny policy means intern
	// WRITE now falls through to default deny (not an explicit deny).
	allowResp, err := checkAccess(env.client, "usr-admin", map[string]*pb.AttributeValues{
		"role": {Values: []string{"admin"}},
	}, "document", "READ")
	if err != nil {
		t.Fatalf("unexpected CheckAccess error: %v", err)
	}
	if !allowResp.Allowed || allowResp.MatchedPolicyId != "pol-count-001" {
		t.Fatalf("expected pol-count-001 to allow admin READ, got allowed=%v matched=%q",
			allowResp.Allowed, allowResp.MatchedPolicyId)
	}

	denyResp, err := checkAccess(env.client, "usr-intern", map[string]*pb.AttributeValues{
		"role": {Values: []string{"intern"}},
	}, "document", "WRITE")
	if err != nil {
		t.Fatalf("unexpected CheckAccess error: %v", err)
	}
	if denyResp.Allowed {
		t.Fatalf("expected intern WRITE to be denied after deleting pol-count-002, got allowed (matched=%q)",
			denyResp.MatchedPolicyId)
	}
	if denyResp.MatchedPolicyId != "" {
		t.Errorf("expected implicit default deny (empty matched id) after deleting the deny policy, got %q",
			denyResp.MatchedPolicyId)
	}
}
