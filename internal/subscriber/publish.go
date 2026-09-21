package subscriber

import (
	"context"
	"os"

	"github.com/redis/go-redis/v9"
)

const (
	// StreamKey is the Redis stream that carries live policy updates.
	StreamKey = "authpolicy:events"

	// ActionUpsert inserts or replaces a policy. ActionDelete removes one.
	ActionUpsert = "UPSERT"
	ActionDelete = "DELETE"

	// DefaultAddr is used when REDIS_ADDR is unset.
	DefaultAddr = "localhost:6379"
)

// AddrFromEnv returns REDIS_ADDR, or DefaultAddr when it is empty.
func AddrFromEnv() string {
	if v := os.Getenv("REDIS_ADDR"); v != "" {
		return v
	}
	return DefaultAddr
}

// Publish appends one policy update to streamKey. policyJSON may be empty for
// DELETE. Field names match what PolicyUpdateSubscriber reads.
func Publish(ctx context.Context, client *redis.Client, streamKey, action, policyID, policyJSON string) error {
	values := map[string]any{
		"action":    action,
		"policy_id": policyID,
	}
	if policyJSON != "" {
		values["policy_json"] = policyJSON
	}
	return client.XAdd(ctx, &redis.XAddArgs{
		Stream: streamKey,
		ID:     "*",
		Values: values,
	}).Err()
}
