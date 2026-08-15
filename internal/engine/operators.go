package engine

import (
	"github.com/casuncio/bouncer-engine/internal/store"
)

func EvaluateCondition(cond store.Condition, attributes map[string][]string) bool {
	// get the attribute value from request that cooresponds to this condition
	requestVal, exists := attributes[cond.Attribute]

	// attribute value for this condtion not found
	if !exists {
		return false
	}

	switch cond.Operator {
	case "EQUALS":
		return evalEquals(cond.Value, requestVal)
	case "CONTAINS_ALL":
		return evalContainsAll(cond.Value, requestVal)
	case "CONTAINS_ANY":
		return evalContainsAny(cond.Value, requestVal)
	default:
		return false // unknown operator
	}
}

// Operators

// Equals
func evalEquals(condValues []string, requestValues []string) bool {
	// Future: look for optimizations here
	// Fast fail if lengths are not equal
	if len(condValues) != len(requestValues) {
		return false
	}

	// Using Frequency map
	counts := make(map[string]int, len(condValues))

	for _, value := range condValues {
		counts[value]++
	}

	for _, value := range requestValues {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}

	return true
}

// Contains All
func evalContainsAll(condValues []string, requestValues []string) bool {
	// Trivial case, there are no conditions
	if len(condValues) == 0 {
		return true
	}

	// Trivial case, there are more condition values the requet values
	// also covers len(requestValues) == 0
	if len(condValues) > len(requestValues) {
		return false
	}

	reqMap := make(map[string]bool, len(requestValues))

	for _, val := range requestValues {
		reqMap[val] = true
	}

	// possibly faster to use a map
	for _, value := range condValues {
		if !reqMap[value] {
			return false
		}
	}

	return true
}

func evalContainsAny(condValues []string, requestValues []string) bool {
	// Trivial case, there are no conditions
	if len(condValues) == 0 {
		return true
	}

	// Trivial case, there are no request values
	if len(requestValues) == 0 {
		return false
	}

	reqMap := make(map[string]bool, len(requestValues))

	for _, val := range requestValues {
		reqMap[val] = true
	}

	// possibly faster to use a map
	for _, value := range condValues {
		if reqMap[value] {
			return true
		}
	}

	return false
}
