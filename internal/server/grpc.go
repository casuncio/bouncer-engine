package server

import (
	"context"

	"github.com/casuncio/bouncer-engine/internal/audit"
	"github.com/casuncio/bouncer-engine/internal/engine"
	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
)

// AuthzServer implements the gRPC AuthorizationService.
// Policy updates are not accepted over gRPC; they arrive on the Redis stream
// consumed by internal/subscriber.
type AuthzServer struct {
	pb.UnimplementedAuthorizationServiceServer
	engine *engine.Engine
	audit  *audit.AuditLogger
}

// NewAuthzServer creates a new gRPC server bound to the ABAC engine.
func NewAuthzServer(e *engine.Engine, a *audit.AuditLogger) *AuthzServer {
	return &AuthzServer{
		engine: e,
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
