// Command seed uploads a fixed set of authorization policies to a running
// bouncer-engine instance via the StreamPolicyUpdates gRPC API, then issues
// a single CheckAccess probe to verify the engine is evaluating requests as
// expected.
//
// It is intended to run before loadtest/checkaccess.js so the k6 test can
// assert correct allow/deny verdicts against a known policy set.
//
// Usage:
//
//	go run ./loadtest/seed                 # uses localhost:50051
//	BOUNCER_TARGET=host:50051 go run ./loadtest/seed
//	make loadtest                          # seeds then runs k6
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// main connects to the bouncer-engine, streams the policies below into it,
// and verifies the resulting policy set with a probe request. Any failure
// is logged and exits non-zero so CI/Make targets can detect a bad seed.
func main() {
	// Engine endpoint, overridable via BOUNCER_TARGET (defaults to the
	// standard local dev port).
	target := os.Getenv("BOUNCER_TARGET")
	if target == "" {
		target = "localhost:50051"
	}

	// Plain-text (no TLS) gRPC channel — appropriate for local dev and
	// load testing. Production deployments should use TLS credentials.
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("failed to connect", "target", target, "error", err)
		os.Exit(1)
	}
	defer conn.Close()
	client := pb.NewAuthorizationServiceClient(conn)

	// Policies are stored as raw JSON strings (matching the engine's
	// PolicyJson wire field) so this tool stays a thin seeder and does not
	// need to know the policy struct schema. The set here must mirror the
	// fixtures expected by loadtest/checkaccess.js — adding/removing a
	// policy here likely requires updating the k6 fixtures too.
	policies := []struct {
		id   string
		json string
	}{
		// ALLOW: SecurityAdmin may READ production-db-backup when the
		// request originates from the corp CIDR (10.0.0.0/8) and is made
		// during business hours (hour between 8 and 18, inclusive).
		{
			id:   "allow-secops",
			json: `{"id":"allow-secops","description":"Allow SecurityAdmin read of production-db-backup from corp CIDR during business hours","access":"ALLOW","target":{"resource_type":"production-db-backup","action":"READ"},"conditions":[{"attribute":"principal.roles","operator":"CONTAINS_ANY","value":["SecurityAdmin"]},{"attribute":"environment.ip_address","operator":"IN_CIDR","value":["10.0.0.0/8"]},{"attribute":"environment.hour","operator":"BETWEEN","value":["8","18"]}]}`,
		},
		// DENY: Contractors are explicitly blocked from
		// production-db-backup regardless of other matching allow policies
		// (explicit deny takes precedence).
		{
			id:   "deny-contractor",
			json: `{"id":"deny-contractor","description":"Explicitly deny contractors access to production-db-backup","access":"DENY","target":{"resource_type":"production-db-backup","action":"READ"},"conditions":[{"attribute":"principal.roles","operator":"CONTAINS_ANY","value":["Contractor"]}]}`,
		},
		// ALLOW: Principals with role=admin may READ the dashboard.
		{
			id:   "allow-dashboard",
			json: `{"id":"allow-dashboard","description":"Allow admins to read the dashboard","access":"ALLOW","target":{"resource_type":"dashboard","action":"READ"},"conditions":[{"attribute":"principal.role","operator":"EQUALS","value":["admin"]}]}`,
		},
	}

	// Open a streaming policy update RPC. All policies are sent on the
	// same stream and committed atomically when CloseAndRecv is called.
	stream, err := client.StreamPolicyUpdates(context.Background())
	if err != nil {
		slog.Error("failed to open policy stream", "error", err)
		os.Exit(1)
	}

	// Upsert each policy one by one. UPSERT keeps this idempotent —
	// re-running seed replaces existing policies with the same id rather
	// than creating duplicates.
	for _, p := range policies {
		if err := stream.Send(&pb.PolicyUpdateRequest{
			PolicyId:   p.id,
			Action:     "UPSERT",
			PolicyJson: p.json,
		}); err != nil {
			slog.Error("failed to send policy", "id", p.id, "error", err)
			os.Exit(1)
		}
	}

	// CloseAndRecv flushes the stream and returns the commit summary,
	// including the total number of active policies now in the engine.
	resp, err := stream.CloseAndRecv()
	if err != nil {
		slog.Error("failed to close policy stream", "error", err)
		os.Exit(1)
	}
	slog.Info("policies seeded", "count", len(policies), "active_policy_count", resp.ActivePolicyCount)

	// Brief pause to let the engine apply the committed policies before we
	// probe. The 50 ms value matches the engine's internal apply cadence;
	// probing too quickly can produce a transient denial.
	time.Sleep(50 * time.Millisecond)

	// Probe: a request that should be ALLOWED by the allow-secops policy
	// (SecurityAdmin, 10.4.4.10 in 10/8, hour 12 in 8–18). If this returns
	// Allowed=false the seed did not take effect and the load test would
	// produce false negatives — fail fast instead.
	probe, err := client.CheckAccess(context.Background(), &pb.CheckAccessRequest{
		PrincipalId:         "usr-1",
		PrincipalAttributes: map[string]*pb.AttributeValues{"roles": {Values: []string{"SecurityAdmin"}}},
		ResourceType:        "production-db-backup",
		Action:              "READ",
		EnvironmentAttributes: map[string]*pb.AttributeValues{
			"ip_address": {Values: []string{"10.4.4.10"}},
			"hour":       {Values: []string{"12"}},
		},
	})
	if err != nil {
		slog.Error("probe CheckAccess failed", "error", err)
		os.Exit(1)
	}
	if !probe.Allowed {
		slog.Error("probe verification failed", "allowed", probe.Allowed, "reason", probe.Reason)
		os.Exit(1)
	}

	// MatchedPolicyId confirms which policy produced the allow verdict,
	// giving confidence the right rule fired (not an unrelated allow).
	slog.Info("seed verification passed", "allowed", probe.Allowed, "matched_policy", probe.MatchedPolicyId, "target", target)
}
