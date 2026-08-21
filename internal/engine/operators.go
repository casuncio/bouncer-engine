package engine

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/casuncio/bouncer-engine/internal/store"
)

func EvaluateCondition(cond store.Condition, req *EvaluationRequest) bool {
	// 1. Zero-allocation split (e.g., "principal.roles" -> "principal", "roles")
	prefix, key, found := strings.Cut(cond.Attribute, ".")
	if !found {
		return false
	}

	var requestValues []string
	var exists bool

	// 2. Route directly to the existing map based on the prefix
	switch prefix {
	case "principal":
		requestValues, exists = req.PrincipalAttributes[key]
	case "resource":
		requestValues, exists = req.ResourceAttributes[key]
	case "environment":
		requestValues, exists = req.EnvironmentAttributes[key]
	default:
		return false
	}
	// attribute value for this condtion not found
	if !exists {
		return false
	}

	switch cond.Operator {
	case "EQUALS":
		return evalEquals(cond.Value, requestValues)
	case "CONTAINS_ALL":
		return evalContainsAll(cond.Value, requestValues)
	case "CONTAINS_ANY":
		return evalContainsAny(cond.Value, requestValues)
	case "IN_CIDR":
		return evalInCIDR(cond.Value, requestValues)
	case "BETWEEN":
		return evalBetween(cond.Value, requestValues)
	case "REGEX":
		return evalRegex(cond.CompiledRegex, requestValues)
	default:
		return false // unknown operator
	}
}

// Operators

// Equals
func evalEquals(condValues []string, requestValues []string) bool {
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
// evaluateInCIDR checks if the single requested IP falls within ANY of the condition's CIDR blocks.
// Uses net/netip for zero-allocation parsing on the stack.
func evalInCIDR(condValues []string, requestValues []string) bool {
	// Trivial check: We need at least one CIDR condition and exactly one request IP
	if len(condValues) == 0 || len(requestValues) != 1 {
		return false
	}

	// 1. Parse the request IP exactly once
	reqIP, err := netip.ParseAddr(requestValues[0])
	if err != nil {
		return false // Fail securely if the incoming IP is malformed
	}

	// 2. Iterate over the policy's allowed CIDR blocks
	for _, cidrStr := range condValues {
		prefix, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			continue // Skip malformed policy CIDRs and check the next one
		}

		// 3. Check if the parsed IP falls inside this specific subnet
		if prefix.Contains(reqIP) {
			return true // Match found!
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
func evalRegex(compiledRegex *regexp.Regexp, requestValues []string) bool {
	// trivial
	if compiledRegex == nil || len(requestValues) == 0 {
		return false
	}

	for _, val := range requestValues {
		if compiledRegex.MatchString(val) {
			return true
		}
	}

	return false
}
