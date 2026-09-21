package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/casuncio/bouncer-engine/internal/subscriber"
	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	engineAddr    = envOr("BOUNCER_ENGINE_ADDR", "bouncer-engine:50051")
	redisAddr     = envOr("REDIS_ADDR", subscriber.DefaultAddr)
	httpbinTarget = envOr("HTTPBIN_TARGET", "http://httpbin")
	listenAddr    = envOr("PEP_LISTEN_ADDR", ":8080")
	policiesDir   = envOr("POLICIES_DIR", "/policies")
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

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer rdb.Close()
	seedPolicies(context.Background(), rdb, policiesDir)

	target, err := url.Parse(httpbinTarget)
	if err != nil {
		slog.Error("invalid httpbin target", "target", httpbinTarget, "error", err)
		os.Exit(1)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principalID := r.Header.Get("X-User")
		if principalID == "" {
			principalID = "anonymous"
		}
		roles := r.Header.Values("X-Role")
		action := actionForMethod(r.Method)
		ip := clientIP(r)

		req := &pb.CheckAccessRequest{
			PrincipalId: principalID,
			PrincipalAttributes: map[string]*pb.AttributeValues{
				"role": {Values: roles},
			},
			ResourceType: "httpbin",
			ResourceId:   r.URL.Path,
			Action:       action,
			EnvironmentAttributes: map[string]*pb.AttributeValues{
				"ip_address": {Values: []string{ip}},
			},
		}

		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		resp, err := client.CheckAccess(ctx, req)
		cancel()
		if err != nil {
			slog.Error("CheckAccess failed",
				"error", err,
				"principal_id", principalID,
				"action", action,
				"path", r.URL.Path,
			)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"allowed": false,
				"reason":  "authorization engine unavailable",
			})
			return
		}

		slog.Info("authz decision",
			"principal_id", principalID,
			"action", action,
			"path", r.URL.Path,
			"allowed", resp.GetAllowed(),
			"matched_policy_id", resp.GetMatchedPolicyId(),
			"reason", resp.GetReason(),
			"latency_ns", resp.GetEvaluationTimeNs(),
		)

		if !resp.GetAllowed() {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"allowed":            false,
				"reason":             resp.GetReason(),
				"matched_policy_id":  resp.GetMatchedPolicyId(),
				"evaluation_time_ns": resp.GetEvaluationTimeNs(),
			})
			return
		}

		proxy.ServeHTTP(w, r)
	})

	slog.Info("bouncer-pep listening",
		"addr", listenAddr,
		"upstream", httpbinTarget,
		"engine", engineAddr,
	)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		slog.Error("pep server stopped", "error", err)
		os.Exit(1)
	}
}

func seedPolicies(ctx context.Context, rdb *redis.Client, dir string) {
	files := loadPolicyFiles(dir)
	if len(files) == 0 {
		slog.Warn("no policy files found; engine will deny everything until policies are loaded", "dir", dir)
		return
	}

	backoff := 500 * time.Millisecond
	maxBackoff := 5 * time.Second
	for attempt := 1; ; attempt++ {
		failed := false
		for _, f := range files {
			if err := subscriber.Publish(ctx, rdb, subscriber.StreamKey, subscriber.ActionUpsert, f.id, f.json); err != nil {
				slog.Warn("failed to publish policy update, retrying",
					"policy_id", f.id, "attempt", attempt, "redis", redisAddr, "error", err)
				failed = true
				break
			}
		}
		if failed {
			sleep(backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		slog.Info("policies seeded into bouncer engine",
			"count", len(files),
			"stream", subscriber.StreamKey,
			"redis", redisAddr,
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

func actionForMethod(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return "READ"
	default:
		return "WRITE"
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func sleep(d time.Duration) {
	time.Sleep(d)
}
