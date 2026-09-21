package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/casuncio/bouncer-engine/internal/subscriber"
	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx := context.Background()

	redisAddr := subscriber.AddrFromEnv()
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "",
		DB:       0,
	})
	defer rdb.Close()

	policyJSON := `{
		"id": "pol-mock-001",
		"description": "Allow Admin Read",
		"access": "ALLOW",
		"target": {"resource_type": "dashboard", "action": "READ"},
		"conditions": [{"attribute": "principal.role", "operator": "EQUALS", "value": ["admin"]}]
	}`

	slog.Info("publishing policy update", "stream", subscriber.StreamKey, "redis", redisAddr)
	if err := subscriber.Publish(ctx, rdb, subscriber.StreamKey, subscriber.ActionUpsert, "pol-mock-001", policyJSON); err != nil {
		slog.Error("failed to publish policy update", "error", err)
		os.Exit(1)
	}

	target := os.Getenv("BOUNCER_TARGET")
	if target == "" {
		target = "localhost:50051"
	}
	conn, err := grpc.Dial(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("failed to connect", "error", err)
		os.Exit(1)
	}
	defer conn.Close()
	client := pb.NewAuthorizationServiceClient(conn)

	// The subscriber applies updates asynchronously. Probe until the upsert
	// is live or the deadline passes.
	deadline := time.Now().Add(5 * time.Second)
	var resp *pb.CheckAccessResponse
	for {
		resp, err = client.CheckAccess(ctx, &pb.CheckAccessRequest{
			PrincipalId:         "usr-1",
			PrincipalAttributes: map[string]*pb.AttributeValues{"role": {Values: []string{"admin"}}},
			ResourceType:        "dashboard",
			Action:              "READ",
		})
		if err == nil && resp.Allowed {
			break
		}
		if time.Now().After(deadline) {
			if err != nil {
				slog.Error("CheckAccess failed", "error", err)
			} else {
				slog.Error("access check did not allow after publish", "allowed", resp.Allowed, "reason", resp.Reason)
			}
			os.Exit(1)
		}
		time.Sleep(20 * time.Millisecond)
	}

	slog.Info("access check complete", "allowed", resp.Allowed, "reason", resp.Reason, "latency_ns", resp.EvaluationTimeNs)
}
