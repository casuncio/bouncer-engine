package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	"github.com/casuncio/bouncer-engine/internal/audit"
	"github.com/casuncio/bouncer-engine/internal/engine"
	"github.com/casuncio/bouncer-engine/internal/metrics"
	"github.com/casuncio/bouncer-engine/internal/server"
	"github.com/casuncio/bouncer-engine/internal/store"
	"github.com/casuncio/bouncer-engine/internal/subscriber"
	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
)

func main() {
	// 1. Initialize structured JSON logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	slog.Info("Initializing Bouncer Engine...", "version", "0.1.0-alpha")

	// 2. Initialize thread safe PolicyStore
	policyStore := store.NewPolicyStore()

	// 2b. Register Prometheus metrics (policy count gauge pulls from the store)
	metrics.Register(policyStore)

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

	// 6. Create Redis Subscriber. Policy updates arrive only on this stream.
	redisAddr := subscriber.AddrFromEnv()
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "",
		DB:       0,
	})
	defer rdb.Close()

	policySubscriber := subscriber.NewPolicyUpdateSubscriber(subscriber.StreamKey, rdb, policyStore)
	go policySubscriber.Start(context.Background())
	slog.Info("redis policy subscriber started", "addr", redisAddr, "stream", subscriber.StreamKey)

	// 7. Create the gRPC Server and register the Bouncer Engine service.
	// The unary interceptor records authz_evaluations_total and
	// authz_evaluation_duration_seconds for every CheckAccess call.
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(metrics.UnaryInterceptor))
	authzServer := server.NewAuthzServer(abacEngine, auditLogger)
	pb.RegisterAuthorizationServiceServer(grpcServer, authzServer)

	// 7b. Serve the Prometheus /metrics endpoint on a separate HTTP port so
	// scrapers never touch the gRPC listener.
	metricsAddr := ":9090"
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(metricsAddr, mux); err != nil {
			slog.Error("metrics server stopped", "error", err)
		}
	}()
	slog.Info("Prometheus metrics endpoint listening", "addr", metricsAddr)

	// 8. Start serving live network traffic
	slog.Info("gRPC server actively listening for authorization checks", "port", port)
	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("gRPC server crashed", "error", err)
		os.Exit(1)
	}
}
