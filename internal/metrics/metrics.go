package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
)

// PolicyCounter is satisfied structurally by *store.PolicyStore. It is declared
// here so this package does not import internal/store, keeping the engine and
// store packages free of any Prometheus dependency.
type PolicyCounter interface {
	Count() int
}

var (
	// evaluationsTotal is a CounterVec over the decision outcome. The two
	// fixed child counters below are curried at registration time so the gRPC
	// interceptor hot path performs a single atomic increment with zero
	// label-map allocations per RPC.
	evaluationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authz_evaluations_total",
			Help: "Total number of authorization evaluations, labelled by access decision (allow|deny).",
		},
		[]string{"access"},
	)

	// allowCounter and denyCounter are pre-resolved child counters. Selecting
	// between them is a single branch, and .Inc() is an atomic uint64 add.
	allowCounter prometheus.Counter
	denyCounter  prometheus.Counter

	// evaluationDurationSeconds reports the engine's own evaluation time
	// (CheckAccessResponse.evaluation_time_ns), not gRPC end-to-end wall time,
	// so it reflects pure PDP cost. Buckets span the project's <2ms p99 target
	// up to a generous 2.5s ceiling for pathological cases.
	evaluationDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "authz_evaluation_duration_seconds",
			Help:    "Time spent evaluating an authorization request, in seconds, as reported by the engine.",
			Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		},
	)

	// policyCount is a pull-style gauge: its value is recomputed on every
	// scrape by calling PolicyCounter.Count(), so policy mutations pay nothing.
	policyCount = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "authz_policy_count",
			Help: "Number of policies currently held in the in-memory store (allow + deny tables).",
		},
		func() float64 {
			if registeredCounter == nil {
				return 0
			}
			return float64(registeredCounter.Count())
		},
	)

	registeredCounter PolicyCounter
)

// Register installs all Bouncer Engine metrics on the default Prometheus
// registry. It must be called exactly once at startup, after the policy store
// is constructed. Calling it more than once panics (prometheus.Register
// behavior), which surfaces double-wiring immediately during development.
func Register(pc PolicyCounter) {
	registeredCounter = pc

	// Curry the CounterVec into fixed child counters so the hot path avoids
	// re-resolving labels on every RPC.
	var err error
	allowCounter, err = evaluationsTotal.GetMetricWithLabelValues("allow")
	if err != nil {
		panic("metrics: failed to curry allow counter: " + err.Error())
	}
	denyCounter, err = evaluationsTotal.GetMetricWithLabelValues("deny")
	if err != nil {
		panic("metrics: failed to curry deny counter: " + err.Error())
	}

	prometheus.MustRegister(
		evaluationsTotal,
		evaluationDurationSeconds,
		policyCount,
	)
}

// UnaryInterceptor is a grpc.UnaryServerInterceptor that records the
// authorization decision and engine-reported evaluation latency for every
// CheckAccess RPC. Other unary methods (currently none besides CheckAccess)
// pass through untouched.
//
// On a handler error the response is nil, so no decision counter is bumped and
// no duration is observed: the engine never produced an EvaluationTimeNs. The
// error is returned to the client unchanged.
func UnaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	resp, err := handler(ctx, req)
	if err != nil {
		return resp, err
	}

	authzResp, ok := resp.(*pb.CheckAccessResponse)
	if !ok || authzResp == nil {
		return resp, err
	}

	if authzResp.Allowed {
		allowCounter.Inc()
	} else {
		denyCounter.Inc()
	}
	evaluationDurationSeconds.Observe(float64(authzResp.EvaluationTimeNs) / float64(time.Second))

	return resp, err
}
