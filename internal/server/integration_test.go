package server_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/casuncio/bouncer-engine/internal/audit"
	"github.com/casuncio/bouncer-engine/internal/engine"
	"github.com/casuncio/bouncer-engine/internal/server"
	"github.com/casuncio/bouncer-engine/internal/store"
	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func setupTestServer(t *testing.T) pb.AuthorizationServiceClient {
	t.Helper()

	policyStore := store.NewPolicyStore()
	abacEngine := engine.New(policyStore)
	auditLogger := audit.NewAuditLogger(1000)
	auditLogger.Start(2)
	t.Cleanup(auditLogger.Stop)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthorizationServiceServer(grpcServer, server.NewAuthzServer(abacEngine, policyStore, auditLogger))
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

	return pb.NewAuthorizationServiceClient(conn)
}

// applyPolicyUpdates streams the given updates in a single session and asserts
// the server acknowledges them.
func applyPolicyUpdates(t *testing.T, client pb.AuthorizationServiceClient, updates ...*pb.PolicyUpdateRequest) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.StreamPolicyUpdates(ctx)
	if err != nil {
		t.Fatalf("failed to open policy update stream: %v", err)
	}
	for _, update := range updates {
		if err := stream.Send(update); err != nil {
			t.Fatalf("failed to send policy update %q: %v", update.PolicyId, err)
		}
	}
	resp, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("failed to close policy update stream: %v", err)
	}
	if !resp.GetSuccess() {
		t.Fatalf("expected stream acknowledgement success=true, got false")
	}
}

func upsertPolicy(id string, access string, resourceType string, action string, conditions string) *pb.PolicyUpdateRequest {
	return &pb.PolicyUpdateRequest{
		PolicyId: id,
		Action:   "UPSERT",
		PolicyJson: `{
			"id": "` + id + `",
			"description": "integration test policy",
			"access": "` + access + `",
			"target": {"resource_type": "` + resourceType + `", "action": "` + action + `"},
			"conditions": ` + conditions + `
		}`,
	}
}

func deletePolicy(id string) *pb.PolicyUpdateRequest {
	return &pb.PolicyUpdateRequest{
		PolicyId: id,
		Action:   "DELETE",
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
	client := setupTestServer(t)

	resp, err := checkAccess(client, "usr-1", map[string]*pb.AttributeValues{
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
	client := setupTestServer(t)

	applyPolicyUpdates(t, client,
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
				resp, reqErr := client.CheckAccess(ctx, &pb.CheckAccessRequest{
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
	client := setupTestServer(t)

	const policyID = "pol-integration-002"

	applyPolicyUpdates(t, client,
		upsertPolicy(policyID, "ALLOW", "document", "READ",
			`[{"attribute": "principal.role", "operator": "EQUALS", "value": ["editor"]}]`),
	)

	resp, err := checkAccess(client, "usr-2", map[string]*pb.AttributeValues{
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

	applyPolicyUpdates(t, client, deletePolicy(policyID))

	resp, err = checkAccess(client, "usr-2", map[string]*pb.AttributeValues{
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

func TestIntegration_StreamInvalidPolicyJson_ContinuesServing(t *testing.T) {
	client := setupTestServer(t)

	applyPolicyUpdates(t, client,
		&pb.PolicyUpdateRequest{
			PolicyId:   "pol-broken-json",
			Action:     "UPSERT",
			PolicyJson: `{ this is not valid json `,
		},
		upsertPolicy("pol-recovery-001", "ALLOW", "document", "WRITE",
			`[{"attribute": "principal.role", "operator": "EQUALS", "value": ["admin"]}]`),
	)

	resp, err := checkAccess(client, "usr-admin", map[string]*pb.AttributeValues{
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
	client := setupTestServer(t)

	applyPolicyUpdates(t, client,
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
			resp, err := client.CheckAccess(context.Background(), &pb.CheckAccessRequest{
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

func TestIntegration_DenyPolicy_RejectedAtIngest(t *testing.T) {
	client := setupTestServer(t)

	applyPolicyUpdates(t, client,
		upsertPolicy("pol-deny-001", "DENY", "document", "WRITE",
			`[{"attribute": "principal.role", "operator": "EQUALS", "value": ["intern"]}]`),
	)

	resp, err := checkAccess(client, "usr-intern", map[string]*pb.AttributeValues{
		"role": {Values: []string{"intern"}},
	}, "document", "WRITE")
	if err != nil {
		t.Fatalf("unexpected CheckAccess error: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected denied for intern")
	}
	if resp.MatchedPolicyId == "pol-deny-001" {
		t.Error("DENY policy must be rejected at ingest and never match requests")
	}
	if resp.MatchedPolicyId != "" {
		t.Errorf("expected default deny with no matched policy, got %q (reason: %s)", resp.MatchedPolicyId, resp.Reason)
	}
}
