package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"

	"github.com/casuncio/bouncer-engine/internal/engine"
	"github.com/casuncio/bouncer-engine/internal/store"
	pb "github.com/casuncio/bouncer-engine/pkg/gen/authzv1"
)

// AuthzServer implements the gRPC AuthorizationService
type AuthzServer struct {
	pb.UnimplementedAuthorizationServiceServer
	engine *engine.Engine
	store  *store.PolicyStore
}

// NewAuthzServer creates a new gRPC server bound to your ABAC engine
func NewAuthzServer(e *engine.Engine, s *store.PolicyStore) *AuthzServer {
	return &AuthzServer{
		engine: e,
		store:  s,
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

	// 3. Map internal EvaluationResponse back to Protobuf response
	return &pb.CheckAccessResponse{
		Allowed:          evalResp.Allowed,
		MatchedPolicyId:  evalResp.MatchedPolicyID,
		Reason:           evalResp.Reason,
		EvaluationTimeNs: evalResp.EvaluationTimeNs,
	}, nil
}

// processUpdate helper function
func (s *AuthzServer) processUpdate(req *pb.PolicyUpdateRequest) {
	switch req.Action {
	case "UPSERT":
		var p store.Policy
		if err := json.Unmarshal([]byte(req.PolicyJson), &p); err != nil {
			slog.Error("Failed to parse policy JSON", "id", req.PolicyId, "error", err)
			return
		}
		s.store.UpsertPolicy(p)
		slog.Info("Policy hot-reloaded successfully", "id", req.PolicyId)

	case "DELETE":
		s.store.DeletePolicy(req.PolicyId)
		slog.Info("Policy deleted successfully", "id", req.PolicyId)
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
