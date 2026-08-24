// Package main is the bouncer-engine ext_authz adapter.
//
// It implements Envoy's envoy.service.auth.v3.Authorization gRPC service. On
// every Check RPC it reads the already-JWT-verified payload that Envoy's
// jwt_authn filter attached (via forward_payload_header), maps the claims to a
// bouncer-engine CheckAccessRequest, calls the engine, and returns an
// OkHttpResponse (allow) or DeniedHttpResponse (deny / fail-closed).
//
// The adapter deliberately performs NO JWT verification: Envoy owns the crypto
// against Dex's JWKS. This keeps the adapter thin and matches the production
// split where authn happens at the edge and fine-grained authz happens in the
// PDP.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpc "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
)

var (
	engineAddr     = envOr("BOUNCER_ENGINE_ADDR", "bouncer-engine:50051")
	listenAddr     = envOr("EXTAUTHZ_LISTEN_ADDR", ":9191")
	policiesDir    = envOr("POLICIES_DIR", "/policies")
	payloadHeader  = strings.ToLower(envOr("JWT_PAYLOAD_HEADER", "x-jwt-payload"))
	engineTimeout  = 2 * time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	conn, err := grpc.Dial(engineAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("failed to dial bouncer engine", "addr", engineAddr, "error", err)
		os.Exit(1)
	}
	defer conn.Close()
	client := pb.NewAuthorizationServiceClient(conn)

	seedPolicies(context.Background(), client, policiesDir)

	srv := &extAuthzServer{client: client}

	grpcSrv := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcSrv, srv)

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		slog.Error("failed to bind ext_authz listener", "addr", listenAddr, "error", err)
		os.Exit(1)
	}

	// Graceful stop on SIGTERM/SIGINT so Envoy sees a clean connection reset
	// rather than a mid-stream error when the container is restarted.
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		slog.Info("ext_authz adapter shutting down")
		grpcSrv.GracefulStop()
	}()

	slog.Info("bouncer-extauthz listening",
		"addr", listenAddr,
		"engine", engineAddr,
		"payload_header", payloadHeader,
	)
	if err := grpcSrv.Serve(lis); err != nil {
		slog.Error("ext_authz server stopped", "error", err)
		os.Exit(1)
	}
}

// extAuthzServer implements envoy.service.auth.v3.AuthorizationServer.
type extAuthzServer struct {
	client pb.AuthorizationServiceClient
}

// Check is the per-request ext_authz entry point. Envoy calls it synchronously
// before forwarding to the upstream; the returned CheckResponse either permits
// the request or short-circuits it with a denial.
func (s *extAuthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpAttrs := req.GetAttributes().GetRequest().GetHttp()
	headers := httpAttrs.GetHeaders()

	claims, err := extractClaims(headers)
	if err != nil {
		slog.Info("authz decision: reject unauthenticated request",
			"reason", err.Error(),
			"path", httpAttrs.GetPath(),
			"method", httpAttrs.GetMethod(),
		)
		return denyJSON(http.StatusUnauthorized, map[string]any{
			"allowed": false,
			"reason":  err.Error(),
		}), nil
	}

	path := httpAttrs.GetPath()
	method := httpAttrs.GetMethod()
	action := actionForMethod(method)
	ip := sourceIP(req)
	roles := enrichRoles(claims)

	authzReq := &pb.CheckAccessRequest{
		PrincipalId: claims.Subject,
		PrincipalAttributes: map[string]*pb.AttributeValues{
			"role": {Values: roles},
		},
		ResourceType: "httpbin",
		ResourceId:   path,
		ResourceAttributes: map[string]*pb.AttributeValues{
			"path": {Values: []string{path}},
		},
		Action: action,
		EnvironmentAttributes: map[string]*pb.AttributeValues{
			"ip_address": {Values: []string{ip}},
		},
	}

	cctx, cancel := context.WithTimeout(ctx, engineTimeout)
	resp, err := s.client.CheckAccess(cctx, authzReq)
	cancel()
	if err != nil {
		slog.Error("CheckAccess failed",
			"error", err,
			"principal_id", claims.Subject,
			"action", action,
			"path", path,
		)
		return denyJSON(http.StatusServiceUnavailable, map[string]any{
			"allowed": false,
			"reason":  "authorization engine unavailable",
		}), nil
	}

	slog.Info("authz decision",
		"principal_id", claims.Subject,
		"email", claims.Email,
		"action", action,
		"path", path,
		"method", method,
		"roles", roles,
		"allowed", resp.GetAllowed(),
		"matched_policy_id", resp.GetMatchedPolicyId(),
		"reason", resp.GetReason(),
		"latency_ns", resp.GetEvaluationTimeNs(),
	)

	if !resp.GetAllowed() {
		return denyJSON(http.StatusForbidden, map[string]any{
			"allowed":            false,
			"reason":             resp.GetReason(),
			"matched_policy_id":  resp.GetMatchedPolicyId(),
			"evaluation_time_ns": resp.GetEvaluationTimeNs(),
		}), nil
	}

	// Forward the verified identity downstream so httpbin's echo can show it.
	// In a real deployment these would be the trusted headers the upstream
	// keys off, stripped of any client-supplied originals by Envoy.
	return &authv3.CheckResponse{
		Status: &rpc.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: []*corev3.HeaderValueOption{
					mutableHeader("x-user", claims.Subject),
					mutableHeader("x-email", claims.Email),
					mutableHeader("x-roles", strings.Join(roles, ",")),
				},
			},
		},
	}, nil
}

// jwtClaims is the subset of the id_token payload the adapter reads.
//
// `groups` is populated by Dex when an upstream connector that supports group
// claims is used (LDAP, GitHub, Keycloak, ...). Dex's local connector does NOT
// emit groups, so when `groups` is empty the adapter enriches the identity from
// the demoClaimMap keyed by `email` -- see enrichRoles below.
type jwtClaims struct {
	Subject string   `json:"sub"`
	Email   string   `json:"email"`
	Groups  []string `json:"groups"`
}

// extractClaims reads the base64url JWT payload that Envoy's jwt_authn filter
// attached via forward_payload_header. The adapter never touches the JWT
// signature: if the header is absent or unparseable, the request is rejected
// as unauthenticated (Envoy should never reach us without it).
func extractClaims(headers map[string]string) (jwtClaims, error) {
	var claims jwtClaims
	raw, ok := lookupHeader(headers, payloadHeader)
	if !ok {
		return claims, fmt.Errorf("verified JWT payload header %q not present", payloadHeader)
	}
	dec, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		// Some JWT libs pad; try the padded variant before giving up.
		dec, err = base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return claims, fmt.Errorf("JWT payload is not valid base64url: %v", err)
		}
	}
	if err := json.Unmarshal(dec, &claims); err != nil {
		return claims, fmt.Errorf("JWT payload is not valid JSON: %v", err)
	}
	if claims.Subject == "" {
		return claims, fmt.Errorf("JWT payload missing 'sub' claim")
	}
	if claims.Groups == nil {
		claims.Groups = []string{}
	}
	return claims, nil
}

// enrichRoles returns the role set the engine should evaluate against.
//
// Production path: if the JWT already carries a non-empty `groups` claim (a
// real upstream connector did the work), it is used verbatim and the claim map
// is never consulted. This is the zero-touch path you get with LDAP/Keycloak.
//
// Demo path: Dex's local connector emits no groups, so the verified `email` is
// mapped to the demo's role vocabulary. This is claim enrichment at the PEP --
// a standard pattern for translating an IdP's claim vocabulary into the
// application's authorization vocabulary. The map below is a demo artifact; in
// a real deployment this lookup would live in your IdP, an IdP-side claim
// script, or a directory service -- not hardcoded in the adapter.
var demoClaimMap = map[string][]string{
	"alice@bouncer.dev":   {"admin"},
	"bob@bouncer.dev":     {"user"},
	"carol@bouncer.dev":   {"admin", "finance"},
	"mallory@bouncer.dev": {"blocked"},
}

func enrichRoles(c jwtClaims) []string {
	if len(c.Groups) > 0 {
		return c.Groups
	}
	if roles, ok := demoClaimMap[strings.ToLower(c.Email)]; ok {
		return roles
	}
	return []string{}
}

// actionForMethod maps HTTP verbs to the bouncer-engine action vocabulary.
// Safe methods -> READ, everything else -> WRITE.
func actionForMethod(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "READ"
	default:
		return "WRITE"
	}
}

// sourceIP extracts the caller IP from the CheckRequest's source address.
// Envoy populates this from the downstream connection; falls back to "" if
// absent (the IN_CIDR operator then simply won't match, which is fail-safe).
func sourceIP(req *authv3.CheckRequest) string {
	addr := req.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress()
	if addr == "" {
		return "0.0.0.0"
	}
	return addr
}

// denyJSON builds a DeniedHttpResponse carrying a JSON body. Every denial this
// adapter emits is JSON so clients always see the same shape regardless of
// whether the rejection came from missing auth, the engine, or fail-closed.
func denyJSON(httpStatus int, body any) *authv3.CheckResponse {
	payload, _ := json.Marshal(body)
	return &authv3.CheckResponse{
		Status: &rpc.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: httpStatusCode(httpStatus)},
				Body:   string(payload),
				Headers: []*corev3.HeaderValueOption{
					mutableHeader("content-type", "application/json"),
				},
			},
		},
	}
}

// httpStatusCode maps a standard net/http status int to Envoy's
// envoy.type.v3.StatusCode enum. Only the statuses this adapter emits are
// mapped; anything else falls back to Forbidden, which is fail-safe.
func httpStatusCode(status int) typev3.StatusCode {
	switch status {
	case http.StatusUnauthorized:
		return typev3.StatusCode_Unauthorized
	case http.StatusForbidden:
		return typev3.StatusCode_Forbidden
	case http.StatusServiceUnavailable:
		return typev3.StatusCode_ServiceUnavailable
	default:
		return typev3.StatusCode_Forbidden
	}
}

// mutableHeader builds a HeaderValueOption with the append action, so Envoy
// adds (rather than replaces) on allow, and sets the header on deny responses.
func mutableHeader(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{Key: key, Value: value},
	}
}

// lookupHeader does a case-insensitive header lookup. Envoy lowercases all
// header keys, but be defensive in case of proxy edge cases.
func lookupHeader(headers map[string]string, key string) (string, bool) {
	if v, ok := headers[key]; ok {
		return v, true
	}
	lk := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == lk {
			return v, true
		}
	}
	return "", false
}

// ---- policy seeding (mirrors examples/httpbin/pep/main.go) ----

func seedPolicies(ctx context.Context, client pb.AuthorizationServiceClient, dir string) {
	files := loadPolicyFiles(dir)
	if len(files) == 0 {
		slog.Warn("no policy files found; engine will deny everything until policies are loaded", "dir", dir)
		return
	}

	backoff := 500 * time.Millisecond
	maxBackoff := 5 * time.Second
	for attempt := 1; ; attempt++ {
		stream, err := client.StreamPolicyUpdates(ctx)
		if err != nil {
			slog.Warn("failed to open policy stream, retrying", "attempt", attempt, "error", err)
			sleep(backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		failed := false
		for _, f := range files {
			if err := stream.Send(&pb.PolicyUpdateRequest{
				PolicyId:   f.id,
				Action:     "UPSERT",
				PolicyJson: f.json,
			}); err != nil {
				slog.Warn("failed to send policy update, retrying",
					"policy_id", f.id, "attempt", attempt, "error", err)
				failed = true
				break
			}
		}
		if failed {
			sleep(backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		resp, err := stream.CloseAndRecv()
		if err != nil {
			slog.Warn("failed to close policy stream, retrying", "attempt", attempt, "error", err)
			sleep(backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		slog.Info("policies seeded into bouncer engine",
			"count", len(files),
			"active_policy_count", resp.GetActivePolicyCount(),
		)
		return
	}
}

type policyFile struct {
	id   string
	json string
}

func loadPolicyFiles(dir string) []policyFile {
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Error("cannot read policies dir", "dir", dir, "error", err)
		return nil
	}
	var out []policyFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Error("cannot read policy file", "path", path, "error", err)
			continue
		}
		var meta struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(data, &meta); err != nil {
			slog.Error("cannot parse policy file", "path", path, "error", err)
			continue
		}
		if meta.ID == "" {
			slog.Error("policy file missing id", "path", path)
			continue
		}
		out = append(out, policyFile{id: meta.ID, json: string(data)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func sleep(d time.Duration) { time.Sleep(d) }
