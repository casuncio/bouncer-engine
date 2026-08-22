package main

import (
	"context"
	"log/slog"
	"net"
	"os"

	"google.golang.org/grpc"

	"github.com/casuncio/bouncer-engine/internal/audit"
	"github.com/casuncio/bouncer-engine/internal/engine"
	"github.com/casuncio/bouncer-engine/internal/server"
	"github.com/casuncio/bouncer-engine/internal/store"
	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
)

// dummyProvider temporarily satisfies the PolicyProvider interface
// until the thread-safe In-Memory Policy Store is fully integrated.
type dummyProvider struct{}

func (d *dummyProvider) ListActivePolicies(ctx context.Context) ([]store.Policy, error) {
	return []store.Policy{}, nil
}

func main() {
	// 1. Initialize structured JSON logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("Initializing Bouncer Engine...", "version", "0.1.0-alpha")

	// 2. Initialize thread safe PolicyStore
	policyStore := store.NewPolicyStore()

	// 3. Initialize Core PDP(Policy Decision Point) abac engine
	abacEngine := engine.New(policyStore)

	// 4. Set up the TCP network listener
	port := ":50051"
	lis, err := net.Listen("tcp", port)
	if err != nil {
		slog.Error("Failed to bind TCP port", "error", err)
		os.Exit(1)
	}

	// 5. Create audit logger and start log workers
	auditLogger := audit.NewAuditLogger(10000)
	auditLogger.Start(5)
	defer auditLogger.Stop()

	// 6. Create the gRPC Server and register the Bouncer Engine service
	grpcServer := grpc.NewServer()
	authzServer := server.NewAuthzServer(abacEngine, policyStore, auditLogger)
	pb.RegisterAuthorizationServiceServer(grpcServer, authzServer)

	// 7. Start serving live network traffic
	slog.Info("gRPC server actively listening for authorization checks", "port", port)
	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("gRPC server crashed", "error", err)
		os.Exit(1)
	}
}
