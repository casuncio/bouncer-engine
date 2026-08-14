package store

// Access, the outcome of matched policy
type Access string

const (
	AccessAllow Access = "ALLOW"
	AccessDeny  Access = "DENY"
)

// Policy represents a single Attribute-Based Access Control rule
type Policy struct {
	ID          string      `json:"id"`
	Description string      `json:"description"`
	Access      Access      `json:"access"`
	Target      Target      `json:"target"`
	Conditions  []Condition `json:"conditions"`
}

// Target represents scope of the policy,
// access for action on a specific resource
type Target struct {
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
}

// Condition defines a specific dynamic rule that must be met
type Condition struct {
	Attribute string   `json:"attribute"`
	Operator  string   `json:"operator"`
	Value     []string `json:"value"`
}
