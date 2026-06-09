// Package generator produces Alloy specifications from IR.
package generator

import (
	"regexp"
	"strings"
)

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

type TypeDef struct {
	Name     string
	Abstract bool
	Extends  string
	Sigs     []string // For "one sig X, Y extends Parent {}"
}

type Signature struct {
	Name     string
	Abstract bool
	Extends  string
	OneOf    bool
	Fields   []Field
}

type Field struct {
	Name         string
	Type         string
	Multiplicity string // "one", "lone", "set", "seq"
}

type ConcreteResource struct {
	Name    string
	Extends string
}

type Predicate struct {
	Name    string
	Params  []string
	Body    string
	Comment string
}

type Assertion struct {
	Name    string
	Body    string
	Comment string
}

type Check struct {
	AssertionName string
	Scope         string
}

// HasWildcardActions returns true when any action in the list contains a wildcard (*).
func HasWildcardActions(actions []string) bool {
	for _, a := range actions {
		if strings.Contains(a, "*") {
			return true
		}
	}
	return false
}

// ExpandAnalyzableActions filters a list of IAM action strings to explicit S3 actions only.
func ExpandAnalyzableActions(actions []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, a := range actions {
		a = strings.TrimSpace(a)
		if a == "" || a == "*" {
			continue
		}

		parts := strings.SplitN(a, ":", 2)
		if len(parts) == 2 {
			service := strings.ToLower(parts[0])
			// Skip wildcard actions.
			if strings.Contains(parts[1], "*") {
				continue
			}
			// Only S3 actions are within scope.
			if service != "s3" {
				continue
			}
		}

		if !seen[a] {
			seen[a] = true
			result = append(result, a)
		}
	}

	return result
}

func HumanAction(action string) string {
	parts := strings.SplitN(action, "_", 2)
	if len(parts) != 2 {
		return action
	}
	return strings.ToLower(parts[0]) + ":" + parts[1]
}

// AlloyID converts a Terraform name to a valid Alloy identifier.
func AlloyID(name string) string {
	name = strings.ReplaceAll(name, "-", "_")
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	name = re.ReplaceAllString(name, "")
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
	vpce = strings.ToUpper(vpce)
	vpce = strings.ReplaceAll(vpce, "-", "_")
	re := regexp.MustCompile(`[^A-Z0-9_]`)
	vpce = re.ReplaceAllString(vpce, "")
	return vpce
}

// ActionToAlloyID converts an IAM action to an Alloy identifier (s3:GetObject → S3_GetObject).
func ActionToAlloyID(action string) string {
	parts := strings.SplitN(action, ":", 2)
	if len(parts) == 2 {
		service := strings.ToUpper(parts[0])
		op := parts[1]
		if op == "*" {
			return service + "_All"
		}
		return service + "_" + op
	}
	return strings.ReplaceAll(action, ":", "_")
}

func BoolToAlloy(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

func FormatAlloySet(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, " + ")
}
