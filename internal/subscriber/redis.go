package subscriber

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/casuncio/bouncer-engine/internal/store"
	"github.com/redis/go-redis/v9"
)

type PolicyUpdateSubscriber struct {
	streamKey string
	client    *redis.Client
	store     *store.PolicyStore
}

func NewPolicyUpdateSubscriber(streamKey string, client *redis.Client, store *store.PolicyStore) *PolicyUpdateSubscriber {
	return &PolicyUpdateSubscriber{
		streamKey: streamKey,
		client:    client,
		store:     store,
	}
}

func (sub *PolicyUpdateSubscriber) Start(ctx context.Context) {
	slog.Info("starting redis stream subscriber",
		slog.String("stream_key", sub.streamKey),
	)

	// we want to get all policy updates incase we missed any
	lastID := "0"

	for {
		if err := ctx.Err(); err != nil {
			slog.Info("redis stream subscriber stopped", slog.String("reason", err.Error()))
			return
		}

		// Execute XREAD command, blocking for up to 5 seconds if no data is present
		streams, err := sub.client.XRead(ctx, &redis.XReadArgs{
			Streams: []string{sub.streamKey, lastID},
			Count:   1,
			Block:   5 * time.Second,
		}).Result()

		if err == redis.Nil {
			continue
		} else if err != nil {
			if ctx.Err() != nil {
				slog.Info("redis stream subscriber stopped", slog.String("reason", ctx.Err().Error()))
				return
			}
			slog.Error("error reading from stream",
				slog.String("error", err.Error()),
			)
			select {
			case <-ctx.Done():
				slog.Info("redis stream subscriber stopped", slog.String("reason", ctx.Err().Error()))
				return
			case <-time.After(1 * time.Second):
			}
			continue
		}

		for _, stream := range streams {
			for _, entry := range stream.Messages {
				sub.processMessageEntry(entry.Values)
				lastID = entry.ID
			}
		}
	}
}

func getString(values map[string]any, key string) (string, bool) {
	val, exists := values[key]
	if !exists {
		return "", false
	}

	// Type-assert the interface to a string (or bytes depending on driver behavior)
	strValue, ok := val.(string)
	if !ok {
		return "", false
	}

	return strValue, true
}

func (sub *PolicyUpdateSubscriber) processMessageEntry(values map[string]any) {

	action, ok := getString(values, "action")
	if !ok {
		slog.Error("failed to get action from message")
		return
	}

	policyID, ok := getString(values, "policy_id")
	if !ok {
		slog.Error("failed to get policy_id from message")
		return
	}

	switch action {
	case ActionUpsert:

		policyJsonStr, ok := getString(values, "policy_json")
		if !ok {
			slog.Error("missing policy payload",
				slog.String("policy_id", policyID),
			)
			return
		}

		var p store.Policy
		if err := json.Unmarshal([]byte(policyJsonStr), &p); err != nil {
			slog.Error("failed to parse incoming policy payload",
				slog.String("policy_id", policyID),
				slog.String("error", err.Error()),
			)
			return
		}

		if p.Access != store.AccessAllow && p.Access != store.AccessDeny {
			slog.Error("rejected policy payload: unsupported access mode",
				slog.String("policy_id", policyID),
				slog.String("access", string(p.Access)),
			)
			return
		}

		if err := p.Compile(); err != nil {
			slog.Error("failed to compile incoming policy payload",
				slog.String("policy_id", policyID),
				slog.String("error", err.Error()),
			)
			return
		}

		sub.store.UpsertPolicy(p)
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
	case ActionDelete:
		sub.store.DeletePolicy(policyID)
		slog.Info("policy removed from live cache",
			slog.String("policy_id", policyID),
		)
	default:
		slog.Error("unsupported action",
			slog.String("policy_id", policyID),
			slog.String("unsupported", action),
		)
	}
}
