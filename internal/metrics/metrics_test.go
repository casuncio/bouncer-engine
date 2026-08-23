package metrics

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/grpc"

	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
)

// stubCounter satisfies PolicyCounter without importing internal/store.
type stubCounter struct{ n int }

func (s *stubCounter) Count() int { return s.n }

// Register touches the default registry, so guard it with sync.Once to keep
// the suite safe under `go test -race` and repeated invocations.
var registerOnce sync.Once

func ensureRegistered() {
	registerOnce.Do(func() {
		Register(&stubCounter{n: 7})
	})
}

// histogramSnapshot reads a Histogram's current sample count and sum out of the
// (write-only) prometheus.Histogram interface via its Collect channel.
func histogramSnapshot(t *testing.T, h prometheus.Histogram) (count uint64, sum float64) {
	t.Helper()
	ch := make(chan prometheus.Metric, 1)
	h.Collect(ch)
	m := <-ch
	pbm := &dto.Metric{}
	if err := m.Write(pbm); err != nil {
		t.Fatalf("histogram Write: %v", err)
	}
	hh := pbm.GetHistogram()
	return hh.GetSampleCount(), hh.GetSampleSum()
}

// allowHandler returns a unary handler that responds with Allowed=true.
func allowHandler(evalNs int64) grpc.UnaryHandler {
	return func(ctx context.Context, req any) (any, error) {
		return &pb.CheckAccessResponse{Allowed: true, EvaluationTimeNs: evalNs}, nil
	}
}

// denyHandler returns a unary handler that responds with Allowed=false.
func denyHandler(evalNs int64) grpc.UnaryHandler {
	return func(ctx context.Context, req any) (any, error) {
		return &pb.CheckAccessResponse{Allowed: false, EvaluationTimeNs: evalNs}, nil
	}
}

func TestUnaryInterceptor_AllowIncrementsAllowCounter(t *testing.T) {
	ensureRegistered()

	beforeAllow := testutil.ToFloat64(allowCounter)
	beforeDeny := testutil.ToFloat64(denyCounter)

	resp, err := UnaryInterceptor(
		context.Background(),
		&pb.CheckAccessRequest{},
		&grpc.UnaryServerInfo{FullMethod: "/authz.v1.AuthorizationService/CheckAccess"},
		allowHandler(2_000_000),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r, ok := resp.(*pb.CheckAccessResponse); !ok || !r.Allowed {
		t.Fatalf("response not passed through unchanged: %+v", resp)
	}

	if got := testutil.ToFloat64(allowCounter) - beforeAllow; got != 1 {
		t.Errorf("allowCounter delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(denyCounter) - beforeDeny; got != 0 {
		t.Errorf("denyCounter delta = %v, want 0", got)
	}
}

func TestUnaryInterceptor_DenyIncrementsDenyCounter(t *testing.T) {
	ensureRegistered()

	beforeAllow := testutil.ToFloat64(allowCounter)
	beforeDeny := testutil.ToFloat64(denyCounter)

	resp, err := UnaryInterceptor(
		context.Background(),
		&pb.CheckAccessRequest{},
		&grpc.UnaryServerInfo{FullMethod: "/authz.v1.AuthorizationService/CheckAccess"},
		denyHandler(1_500_000),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r, ok := resp.(*pb.CheckAccessResponse); !ok || r.Allowed {
		t.Fatalf("response not passed through unchanged: %+v", resp)
	}

	if got := testutil.ToFloat64(allowCounter) - beforeAllow; got != 0 {
		t.Errorf("allowCounter delta = %v, want 0", got)
	}
	if got := testutil.ToFloat64(denyCounter) - beforeDeny; got != 1 {
		t.Errorf("denyCounter delta = %v, want 1", got)
	}
}

func TestUnaryInterceptor_HandlerErrorRecordsNothing(t *testing.T) {
	ensureRegistered()

	beforeAllow := testutil.ToFloat64(allowCounter)
	beforeDeny := testutil.ToFloat64(denyCounter)
	beforeCount, _ := histogramSnapshot(t, evaluationDurationSeconds)

	wantErr := errors.New("boom")
	handler := func(ctx context.Context, req any) (any, error) {
		return nil, wantErr
	}

	_, err := UnaryInterceptor(
		context.Background(),
		&pb.CheckAccessRequest{},
		&grpc.UnaryServerInfo{FullMethod: "/authz.v1.AuthorizationService/CheckAccess"},
		handler,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error not passed through: got %v", err)
	}

	if got := testutil.ToFloat64(allowCounter) - beforeAllow; got != 0 {
		t.Errorf("allowCounter delta = %v, want 0 on error", got)
	}
	if got := testutil.ToFloat64(denyCounter) - beforeDeny; got != 0 {
		t.Errorf("denyCounter delta = %v, want 0 on error", got)
	}
	afterCount, _ := histogramSnapshot(t, evaluationDurationSeconds)
	if afterCount != beforeCount {
		t.Errorf("histogram observed %d samples on error, want 0", afterCount-beforeCount)
	}
}

func TestUnaryInterceptor_NonAuthzResponsePassesThrough(t *testing.T) {
	ensureRegistered()

	beforeAllow := testutil.ToFloat64(allowCounter)
	beforeDeny := testutil.ToFloat64(denyCounter)

	// A handler returning an unrelated type must not panic and must not bump
	// either counter; the interceptor only instruments *pb.CheckAccessResponse.
	handler := func(ctx context.Context, req any) (any, error) {
		return "not-an-authz-response", nil
	}

	resp, err := UnaryInterceptor(
		context.Background(),
		&pb.CheckAccessRequest{},
		&grpc.UnaryServerInfo{FullMethod: "/some.other.Service/Method"},
		handler,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != "not-an-authz-response" {
		t.Fatalf("response not passed through: %v", resp)
	}

	if got := testutil.ToFloat64(allowCounter) - beforeAllow; got != 0 {
		t.Errorf("allowCounter delta = %v, want 0", got)
	}
	if got := testutil.ToFloat64(denyCounter) - beforeDeny; got != 0 {
		t.Errorf("denyCounter delta = %v, want 0", got)
	}
}

func TestUnaryInterceptor_DurationObservedAsSeconds(t *testing.T) {
	ensureRegistered()

	beforeCount, beforeSum := histogramSnapshot(t, evaluationDurationSeconds)

	const evalNs int64 = 3_000_000 // 3 ms
	if _, err := UnaryInterceptor(
		context.Background(),
		&pb.CheckAccessRequest{},
		&grpc.UnaryServerInfo{FullMethod: "/authz.v1.AuthorizationService/CheckAccess"},
		allowHandler(evalNs),
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	afterCount, afterSum := histogramSnapshot(t, evaluationDurationSeconds)
	if afterCount-beforeCount != 1 {
		t.Fatalf("histogram sample count delta = %d, want 1", afterCount-beforeCount)
	}
	wantDelta := float64(evalNs) / 1e9
	if got := afterSum - beforeSum; math.Abs(got-wantDelta) > 1e-12 {
		t.Errorf("histogram sum delta = %v, want %v", got, wantDelta)
	}
}

func TestPolicyCountGauge_ReflectsCounter(t *testing.T) {
	ensureRegistered()

	ch := make(chan prometheus.Metric, 1)
	policyCount.Collect(ch)
	m := <-ch
	pbm := &dto.Metric{}
	if err := m.Write(pbm); err != nil {
		t.Fatalf("gauge Write: %v", err)
	}

	// ensureRegistered wired a stubCounter with Count()==7.
	if got := pbm.GetGauge().GetValue(); got != 7 {
		t.Errorf("authz_policy_count = %v, want 7", got)
	}
}
