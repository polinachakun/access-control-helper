// Package generator produces Alloy specifications from IR.
package generator

import (
	"regexp"
	"strings"
)

// AlloyModel represents the complete Alloy specification.
type AlloyModel struct {
	Header            string
	TypeDefinitions   []TypeDef
	Signatures        []Signature
	ConcreteResources []ConcreteResource
	ExactUniverseFact string
	ConfigFacts       string
	RequestSig        string
	Predicates        []Predicate
	Assertions        []Assertion
	Checks            []Check
}

// TypeDef represents an Alloy type definition.
type TypeDef struct {
	Name     string
	Abstract bool
	Extends  string
	Sigs     []string // For "one sig X, Y extends Parent {}"
}

// Signature represents an Alloy signature.
type Signature struct {
	Name     string
	Abstract bool
	Extends  string
	OneOf    bool
	Fields   []Field
}

// Field represents a field in an Alloy signature.
type Field struct {
	Name         string
	Type         string
	Multiplicity string // "one", "lone", "set", "seq"
}

// ConcreteResource represents a concrete Alloy signature.
type ConcreteResource struct {
	Name    string
	Extends string
}

// Predicate represents an Alloy predicate.
type Predicate struct {
	Name    string
	Params  []string
	Body    string
	Comment string
}

// Assertion represents an Alloy assertion.
type Assertion struct {
	Name    string
	Body    string
	Comment string
}

// Check represents an Alloy check command.
type Check struct {
	AssertionName string
	Scope         string
}

// SupportedActionsByService defines which concrete actions are analyzable.
// Wildcards like s3:* are expanded only to this catalog.
var SupportedActionsByService = map[string][]string{
	"s3": {
		"s3:GetObject",
		"s3:PutObject",
		"s3:ListBucket",
		"s3:DeleteObject",
	},
}

// ExpandAnalyzableActions expands wildcard actions (e.g. s3:*) into
// concrete actions that should appear in the model/report.
func ExpandAnalyzableActions(actions []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, a := range actions {
		a = strings.TrimSpace(a)
		if a == "" || a == "*" {
			continue
		}

		parts := strings.SplitN(a, ":", 2)
		if len(parts) == 2 && parts[1] == "*" {
			service := strings.ToLower(parts[0])
			for _, concrete := range SupportedActionsByService[service] {
				if !seen[concrete] {
					seen[concrete] = true
					result = append(result, concrete)
				}
			}
			continue
		}

		if !seen[a] {
			seen[a] = true
			result = append(result, a)
		}
	}

	return result
}

// HumanAction converts Alloy action IDs back to IAM-like syntax for reporting.
func HumanAction(action string) string {
	parts := strings.SplitN(action, "_", 2)
	if len(parts) != 2 {
		return action
	}
	return strings.ToLower(parts[0]) + ":" + parts[1]
}

// AlloyID converts a Terraform name to a valid Alloy identifier.
func AlloyID(name string) string {
	// Replace hyphens with underscores
	name = strings.ReplaceAll(name, "-", "_")
	// Remove any characters that aren't alphanumeric or underscore
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	name = re.ReplaceAllString(name, "")
	// Ensure it starts with a letter
	if len(name) > 0 && (name[0] >= '0' && name[0] <= '9') {
		name = "r_" + name
	}
	return name
}

// TagToAlloyID converts a tag value to an Alloy identifier.
func TagToAlloyID(tag string) string {
	tag = strings.ToUpper(tag)
	tag = strings.ReplaceAll(tag, "-", "_")
	re := regexp.MustCompile(`[^A-Z0-9_]`)
	tag = re.ReplaceAllString(tag, "")
	return "TAG_" + tag
}

// VpceToAlloyID converts a VPCE ID to an Alloy identifier.
func VpceToAlloyID(vpce string) string {
	// vpce-0a1b2c3d -> VPCE_0A1B2C3D
	vpce = strings.ToUpper(vpce)
	vpce = strings.ReplaceAll(vpce, "-", "_")
	re := regexp.MustCompile(`[^A-Z0-9_]`)
	vpce = re.ReplaceAllString(vpce, "")
	return vpce
}

// ActionToAlloyID converts an IAM action to an Alloy identifier.
func ActionToAlloyID(action string) string {
	// s3:GetObject -> S3_GetObject
	parts := strings.SplitN(action, ":", 2)
	if len(parts) == 2 {
		service := strings.ToUpper(parts[0])
		op := parts[1]
		// Handle wildcards
		if op == "*" {
			return service + "_All"
		}
		return service + "_" + op
	}
	return strings.ReplaceAll(action, ":", "_")
}

// NormalizeActions extracts unique action names from various formats.
func NormalizeActions(actions []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, a := range actions {
		// Handle wildcards
		if a == "*" {
			continue // Skip full wildcards
		}

		id := ActionToAlloyID(a)
		if !seen[id] {
			seen[id] = true
			result = append(result, id)
		}
	}

	return result
}

// BoolToAlloy converts a Go bool to an Alloy Bool reference.
func BoolToAlloy(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// FormatAlloySet formats a slice as an Alloy set expression.
func FormatAlloySet(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, " + ")
}
