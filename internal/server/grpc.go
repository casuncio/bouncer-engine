package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"

	"github.com/casuncio/bouncer-engine/internal/audit"
	"github.com/casuncio/bouncer-engine/internal/engine"
	"github.com/casuncio/bouncer-engine/internal/store"
	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
)

// AuthzServer implements the gRPC AuthorizationService
type AuthzServer struct {
	pb.UnimplementedAuthorizationServiceServer
	engine *engine.Engine
	store  *store.PolicyStore
	audit  *audit.AuditLogger
}

// NewAuthzServer creates a new gRPC server bound to your ABAC engine
func NewAuthzServer(e *engine.Engine, s *store.PolicyStore, a *audit.AuditLogger) *AuthzServer {
	return &AuthzServer{
		engine: e,
		store:  s,
		audit:  a,
	}
}

// mapAttributes translates from ProtoBuf CheckAccessRequest to Engine EvaluationRequest
func mapAttributes(protoAttrs map[string]*pb.AttributeValues) map[string][]string {
	if protoAttrs == nil {
		return nil
	}

	engineAttrs := make(map[string][]string, len(protoAttrs))
	for k, v := range protoAttrs {
		if v != nil {
			engineAttrs[k] = v.Values
		}
	}
	return engineAttrs
}

// CheckAccess will map the incoming gRPC request to your EvaluationRequest
func (s *AuthzServer) CheckAccess(ctx context.Context, req *pb.CheckAccessRequest) (*pb.CheckAccessResponse, error) {

	// 1. Map Protobuf request to internal EvaluationRequest
	evalReq := &engine.EvaluationRequest{
		PrincipalID:           req.PrincipalId,
		PrincipalAttributes:   mapAttributes(req.PrincipalAttributes),
		ResourceType:          req.ResourceType,
		ResourceID:            req.ResourceId,
		ResourceAttributes:    mapAttributes(req.ResourceAttributes),
		Action:                req.Action,
		EnvironmentAttributes: mapAttributes(req.EnvironmentAttributes),
	}

	// 2. Execute the engine
	evalResp, err := s.engine.CheckAccess(ctx, evalReq)
	if err != nil {
		return nil, err
	}

	// 3. Fire and forget the audit log to the bounded channel
	s.audit.LogDecision(audit.AuditLog{
		PrincipalID: req.PrincipalId,
		Action:      req.Action,
		ResourceID:  req.ResourceId,
		Allowed:     evalResp.Allowed,
		Reason:      evalResp.Reason,
		PolicyId:    evalResp.MatchedPolicyID,
		LatencyNs:   evalResp.EvaluationTimeNs,
	})

	// 4. Map internal EvaluationResponse back to Protobuf response
	return &pb.CheckAccessResponse{
		Allowed:          evalResp.Allowed,
		MatchedPolicyId:  evalResp.MatchedPolicyID,
		Reason:           evalResp.Reason,
		EvaluationTimeNs: evalResp.EvaluationTimeNs,
	}, nil
}

func (s *AuthzServer) processUpdate(req *pb.PolicyUpdateRequest) {
	switch req.Action {
	case "UPSERT":
		var p store.Policy
		if err := json.Unmarshal([]byte(req.PolicyJson), &p); err != nil {
			slog.Error("failed to parse incoming policy payload",
				slog.String("policy_id", req.PolicyId),
				slog.String("error", err.Error()),
			)
			return
		}

		if p.Access != store.AccessAllow {
			slog.Error("rejected policy payload: only ALLOW policies are supported",
				slog.String("policy_id", req.PolicyId),
				slog.String("access", string(p.Access)),
			)
			return
		}

		if err := p.Compile(); err != nil {
			slog.Error("failed to compile incoming policy payload",
				slog.String("policy_id", req.PolicyId),
				slog.String("error", err.Error()),
			)
			return
		}

		s.store.UpsertPolicy(p)
		slog.Info("policy upserted into live cache",
			slog.String("policy_id", p.ID),
			slog.String("policy_description", p.Description),
			slog.String("access", string(p.Access)),
			slog.String("resource_type", p.Target.ResourceType),
			slog.String("action", p.Target.Action),
			slog.Int("condition_count", len(p.Conditions)),
		)

		slog.Debug("policy condition details",
			slog.String("policy_id", p.ID),
			slog.Any("conditions", p.Conditions),
		)

	case "DELETE":
		s.store.DeletePolicy(req.PolicyId)
		slog.Info("policy removed from live cache",
			slog.String("policy_id", req.PolicyId),
		)
	}
}

// StreamPolicyUpdates ingests a live stream of policy changes
func (s *AuthzServer) StreamPolicyUpdates(stream pb.AuthorizationService_StreamPolicyUpdatesServer) error {
	slog.Info("Policy sync stream connected")

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			// The client closed the stream
			slog.Info("Policy sync stream closed by client")
			return stream.SendAndClose(&pb.PolicyUpdateResponse{Success: true})
		}
		if err != nil {
			slog.Error("Error reading from policy stream", "error", err)
			return err
		}

		s.processUpdate(req)
	}
}
