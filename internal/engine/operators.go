package engine

import (
	"github.com/casuncio/bouncer-engine/internal/store"
)

func EvaluateCondition(cond store.Condition, attributes map[string]string) bool {
	// get the attribute value from request that cooresponds to this condition
	requestVal, exists := attributes[cond.Attribute]

	// attribute value for this condtion not found
	if !exists {
		return false
	}

	switch cond.Operator {
	case "EQUALS":
		return evalEquals(cond.Value, requestVal)
	default:
		return false // unknown operator
	}
}

// Operators

// Equals
func evalEquals(condValues []string, requestValue string) bool {
	// Should only contain one value
	if len(condValues) != 1 {
		return false
	}

	return requestValue == condValues[0] // compare to first value
}
