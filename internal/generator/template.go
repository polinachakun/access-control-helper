package generator

import (
	"fmt"
	"io"
	"strings"
	"text/template"
)

// AlloyTemplate is the main template for generating Alloy specifications.
const AlloyTemplate = `// ============================================================
//  AUTO-GENERATED from: {{.SourceFile}}
//  AWS policy evaluation
// ============================================================

// -- Type definitions -----------------------------------------
abstract sig TagValue {}
one sig {{.TagValues}} extends TagValue {}

abstract sig VpceId {}
{{range .VpceIds}}one sig {{.}} extends VpceId {}
{{end}}
abstract sig Action {}
one sig {{.ActionValues}} extends Action {}

abstract sig Resource { dependsOn: set Resource }

sig S3Bucket extends Resource {
  envTag:            one TagValue,
  blockPublicAccess: one Bool
}

sig BucketPolicy extends Resource {
  bucket:         one S3Bucket,
  denyAllExcept:  lone VpceId,
  allowPrincipal: lone IAMRole,
  allowActions:   set Action,
  denyActions:    set Action,
  denyPrincipal:  lone IAMRole,
  abacCondition:  one Bool
}

sig IAMRole extends Resource {
  envTag:           one TagValue,
  hasRolePolicy:    one Bool,
  roleAllowActions: set Action
}

abstract sig Bool {}
one sig True, False extends Bool {}

// -- Concrete resources ---------------------------------------
{{range .Buckets}}one sig bucket_{{.}} extends S3Bucket {}
{{end}}{{range .BucketPolicies}}one sig policy_{{.}} extends BucketPolicy {}
{{end}}{{range .Roles}}one sig role_{{.}} extends IAMRole {}
{{end}}
fact ExactUniverse {
  S3Bucket     = {{.BucketUnion}}
  BucketPolicy = {{.BucketPolicyUnion}}
  IAMRole      = {{.RoleUnion}}
  Resource     = S3Bucket + BucketPolicy + IAMRole
}

// -- Configuration facts --------------------------------------
fact ConfigFacts {
{{.ConfigFacts}}
}

// ============================================================
//  PREDICATES
// ============================================================

sig Request {
  principal:  one IAMRole,
  action:     one Action,
  target:     one S3Bucket,
  sourceVpce: lone VpceId
}

{{range .Predicates}}// {{.Comment}}
pred {{.Name}}[{{range $i, $p := .Params}}{{if $i}}, {{end}}{{$p}}{{end}}] {
  {{.Body}}
}

{{end}}
// Step 1b: General Explicit Deny - any Deny statement in bucket policy
pred generalExplicitDeny[req: Request] {
  some bp: BucketPolicy |
    bp.bucket = req.target and
    req.action in bp.denyActions and
    (bp.denyPrincipal = none or bp.denyPrincipal = req.principal)
}

// ============================================================
//  ASSERTIONS - these fail when there's a misconfiguration
// ============================================================
{{range .Assertions}}
// {{.Comment}}
assert {{.Name}} {
  {{.Body}}
}
{{end}}
//
//  ACCESS ASSERTIONS - for each (role, bucket, action) triple
// ============================================================
{{range .AccessAssertions}}
// {{.Comment}}
assert {{.Name}} {
  {{.Body}}
}
{{end}}

// ============================================================
//  CHECKS
// ============================================================
{{range .Checks}}
check {{.AssertionName}}
  {{.Scope}}
{{end}}`

// TemplateData holds data for the Alloy template.
type TemplateData struct {
	SourceFile        string
	TagValues         string
	VpceIds           []string
	ActionValues      string
	Buckets           []string
	BucketPolicies    []string
	Roles             []string
	RCPs              []string
	SCPs              []string
	BucketUnion       string
	BucketPolicyUnion string
	RCPUnion          string
	SCPUnion          string
	RoleUnion         string
	ConfigFacts       string
	Predicates        []Predicate
	Assertions        []Assertion
	Checks            []Check
	AccessAssertions  []Assertion
}

// RenderTemplate renders the Alloy template to a writer.
func RenderTemplate(w io.Writer, data *TemplateData) error {
	funcMap := template.FuncMap{
		"join": strings.Join,
	}

	tmpl, err := template.New("alloy").Funcs(funcMap).Parse(AlloyTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// GenerateConfigFacts generates the ConfigFacts section.
func GenerateConfigFacts(facts []ConfigFact) string {
	var sb strings.Builder

	for i, f := range facts {
		if i > 0 && f.Resource != facts[i-1].Resource {
			sb.WriteString("\n")
		}
		sb.WriteString(fmt.Sprintf("  %s.%s = %s\n", f.Resource, f.Field, f.Value))
	}

	return sb.String()
}

// ConfigFact represents a single fact assignment.
type ConfigFact struct {
	Resource string
	Field    string
	Value    string
}

// BucketFacts holds Alloy facts for an S3 bucket.
type BucketFacts struct {
	TFName            string
	EnvTag            string
	BlockPublicAccess string
}

// BucketPolicyFacts holds Alloy facts for a bucket policy.
type BucketPolicyFacts struct {
	TFName         string
	Bucket         string
	DenyAllExcept  string
	AllowPrincipal string
	AllowActions   string
	AbacCondition  string
	DependsOn      string
}

// RoleFacts holds Alloy facts for an IAM role.
type RoleFacts struct {
	TFName           string
	EnvTag           string
	HasRolePolicy    string
	RoleAllowActions string
}
