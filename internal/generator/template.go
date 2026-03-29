package generator

import (
	"fmt"
	"io"
	"strings"
	"text/template"
)

// AlloyTemplate is the master template for generating 7-layer Alloy specifications.
// It encodes the full AWS S3 policy evaluation order as Alloy predicates and
// generates one assertion per (principal, bucket, action) triple.
const AlloyTemplate = `// ============================================================
//  AUTO-GENERATED from: {{.SourceFile}}
//  AWS S3 Access Control — 7-layer policy evaluation model
// ============================================================

// ── Scalar domains ─────────────────────────────────────────────────────────
abstract sig TagValue {}
one sig {{.TagValues}} extends TagValue {}

abstract sig VpceId {}
{{range .VpceIds}}one sig {{.}} extends VpceId {}
{{end}}
abstract sig Action {}
one sig {{.ActionValues}} extends Action {}

abstract sig Bool {}
one sig True, False extends Bool {}

// ── Resource hierarchy ──────────────────────────────────────────────────────
abstract sig Resource { dependsOn: set Resource }

// S3 Bucket
sig S3Bucket extends Resource {
  envTag:            one TagValue,
  blockPublicAccess: one Bool
}

// Bucket Policy — resource-based policy evaluated at Layer 4
sig BucketPolicy extends Resource {
  bucket:         one S3Bucket,
  denyAllExcept:  lone VpceId,
  allowPrincipal: lone IAMRole,
  allowActions:   set Action,
  denyActions:    set Action,
  denyPrincipal:  lone IAMRole,
  abacCondition:  one Bool
}

// AWS Organizations Resource Control Policy (Layer 2)
abstract sig OrgRCP extends Resource {
  rcpAllowActions: set Action,
  rcpDenyActions:  set Action
}

// AWS Organizations Service Control Policy (Layer 3)
abstract sig OrgSCP extends Resource {
  scpAllowActions: set Action,
  scpDenyActions:  set Action
}

// IAM Role principal — identity policy (Layer 5), boundary (Layer 6), session (Layer 7)
sig IAMRole extends Resource {
  envTag:               one TagValue,
  hasRolePolicy:        one Bool,
  roleAllowActions:     set Action,
  hasBoundary:          one Bool,
  boundaryActions:      set Action,
  hasSessionPolicy:     one Bool,
  sessionPolicyActions: set Action
}

// ── Concrete resources ──────────────────────────────────────────────────────
{{range .Buckets}}one sig bucket_{{.}} extends S3Bucket {}
{{end}}{{range .BucketPolicies}}one sig policy_{{.}} extends BucketPolicy {}
{{end}}{{range .RCPs}}one sig rcp_{{.}} extends OrgRCP {}
{{end}}{{range .SCPs}}one sig scp_{{.}} extends OrgSCP {}
{{end}}{{range .Roles}}one sig role_{{.}} extends IAMRole {}
{{end}}
fact ExactUniverse {
  S3Bucket     = {{.BucketUnion}}
  BucketPolicy = {{.BucketPolicyUnion}}
  OrgRCP       = {{.RCPUnion}}
  OrgSCP       = {{.SCPUnion}}
  IAMRole      = {{.RoleUnion}}
  Resource     = S3Bucket + BucketPolicy + OrgRCP + OrgSCP + IAMRole
}

// ── Configuration facts ─────────────────────────────────────────────────────
fact ConfigFacts {
{{.ConfigFacts}}
}

// ============================================================
//  REQUEST SIGNATURE
// ============================================================

sig Request {
  principal:  one IAMRole,
  action:     one Action,
  target:     one S3Bucket,
  sourceVpce: lone VpceId
}

// ============================================================
//  EVALUATION PREDICATES — AWS 7-layer policy evaluation order
// ============================================================

{{range .Predicates}}// {{.Comment}}
pred {{.Name}}[{{range $i, $p := .Params}}{{if $i}}, {{end}}{{$p}}{{end}}] {
  {{.Body}}
}

{{end}}
// ============================================================
//  SCENARIO ASSERTIONS
// ============================================================
{{range .Assertions}}
// {{.Comment}}
assert {{.Name}} {
  {{.Body}}
}
{{end}}

// ============================================================
//  PER-TRIPLE ACCESS ASSERTIONS — (principal, bucket, action)
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

// TemplateData holds all values injected into the Alloy template.
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
	AccessAssertions  []Assertion
	Checks            []Check
}

// RenderTemplate renders the Alloy template to w.
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

// GenerateConfigFacts generates the ConfigFacts body from a slice of ConfigFact entries.
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

// ConfigFact represents a single field assignment inside a fact block.
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
	DenyActions    string
	DenyPrincipal  string
	AbacCondition  string
	DependsOn      string
}

// RoleFacts holds Alloy facts for an IAM role.
type RoleFacts struct {
	TFName               string
	EnvTag               string
	HasRolePolicy        string
	RoleAllowActions     string
	HasBoundary          string
	BoundaryActions      string
	HasSessionPolicy     string
	SessionPolicyActions string
}

// OrgPolicyFacts holds Alloy facts for an RCP or SCP.
type OrgPolicyFacts struct {
	TFName        string
	SigPrefix     string // "rcp_" or "scp_"
	AllowActionsF string
	DenyActionsF  string
}
