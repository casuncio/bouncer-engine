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

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// 1. Connect to the local Bouncer Engine
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("Failed to connect", "error", err)
		os.Exit(1)
	}
	defer conn.Close()
	client := pb.NewAuthorizationServiceClient(conn)

	// 2. Open the streaming connection
	stream, err := client.StreamPolicyUpdates(context.Background())
	if err != nil {
		slog.Error("Failed to open stream", "error", err)
		os.Exit(1)
	}

	// 3. Push a dynamic policy update
	policyJSON := `{
		"id": "pol-mock-001",
		"description": "Allow Admin Read",
		"access": "ALLOW",
		"target": {"resource_type": "dashboard", "action": "READ"},
		"conditions": [{"attribute": "principal.role", "operator": "EQUALS", "value": ["admin"]}]
	}`

	err = stream.Send(&pb.PolicyUpdateRequest{
		PolicyId:   "pol-mock-001",
		Action:     "UPSERT",
		PolicyJson: policyJSON,
	})
	if err != nil {
		slog.Error("Failed to push policy", "error", err)
	}
	slog.Info("Successfully streamed policy update")
	stream.CloseAndRecv() // Close stream

	// Give the engine a millisecond to atomically swap the pointer
	time.Sleep(10 * time.Millisecond)

	// 4. Verify the policy is active via CheckAccess
	resp, err := client.CheckAccess(context.Background(), &pb.CheckAccessRequest{
		PrincipalId:         "usr-1",
		PrincipalAttributes: map[string]*pb.AttributeValues{"role": {Values: []string{"admin"}}},
		ResourceType:        "dashboard",
		Action:              "READ",
	})
	if err != nil {
		slog.Error("CheckAccess failed", "error", err)
		os.Exit(1)
	}

	slog.Info("Access check complete", "allowed", resp.Allowed, "reason", resp.Reason, "latency_ns", resp.EvaluationTimeNs)
}
