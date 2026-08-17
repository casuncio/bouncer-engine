package engine

import (
	"net"
	"regexp"
	"strconv"

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
	case "IN_CIDR":
		return evalInCIDR(cond.Value, requestVal)
	case "BETWEEN":
		return evalBetween(cond.Value, requestVal)
	case "REGEX":
		return evalRegex(cond.Value, requestVal)
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

// Contains Any
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

// In CIDR
func evalInCIDR(condValues []string, requestValue []string) bool {
	// trivial
	if len(condValues) == 0 || len(requestValue) != 1 {
		return false
	}

	ipAddr := net.ParseIP(requestValue[0])
	if ipAddr == nil {
		// log error
		return false
	}

	for _, condValue := range condValues {
		// parse CIDR
		_, ipNet, err := net.ParseCIDR(condValue)
		if err != nil {
			// log error, continue for now
			continue
		}

		// ipAddr is in one of the accepted CIDRs
		if ipNet.Contains(ipAddr) {
			return true
		}
	}

	return false
}

// Between, handles numerical range check
func evalBetween(condValue []string, requestValue []string) bool {

	// trivial
	if len(condValue) != 2 || len(requestValue) != 1 {
		return false
	}

	lowVal, err := strconv.Atoi(condValue[0])
	if err != nil {
		// log err
		return false
	}

	highVal, err := strconv.Atoi(condValue[1])
	if err != nil {
		// log err
		return false
	}

	val, err := strconv.Atoi(requestValue[0])
	if err != nil {
		// log err
		return false
	}

	return lowVal <= val && highVal >= val
}

// REGEX
func evalRegex(condValue []string, requestValue []string) bool {
	// trivial
	if len(condValue) != 1 || len(requestValue) != 1 {
		return false
	}

	matched, err := regexp.MatchString(condValue[0], requestValue[0])
	if err != nil {
		// log err
		return false
	}
	return matched
}
