package ir

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParsePolicyDocument parses an IAM policy document from JSON.
func ParsePolicyDocument(jsonStr string) (*IAMPolicyDocument, error) {
	if jsonStr == "" {
		return nil, nil
	}

	// Handle escaped JSON (common in Terraform)
	jsonStr = strings.TrimSpace(jsonStr)

	var raw rawPolicyDocument
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON: %w", err)
	}

	doc := &IAMPolicyDocument{
		Version: raw.Version,
		ID:      raw.ID,
	}

	statements, err := normalizeStatements(raw.Statement)
	if err != nil {
		return nil, err
	}
	doc.Statements = statements

	return doc, nil
}

// rawPolicyDocument matches the raw JSON structure.
type rawPolicyDocument struct {
	Version   string          `json:"Version"`
	ID        string          `json:"Id,omitempty"`
	Statement json.RawMessage `json:"Statement"`
}

// rawStatement matches a single statement in raw JSON.
type rawStatement struct {
	SID          string          `json:"Sid,omitempty"`
	Effect       string          `json:"Effect"`
	Action       json.RawMessage `json:"Action,omitempty"`
	NotAction    json.RawMessage `json:"NotAction,omitempty"`
	Resource     json.RawMessage `json:"Resource,omitempty"`
	NotResource  json.RawMessage `json:"NotResource,omitempty"`
	Principal    json.RawMessage `json:"Principal,omitempty"`
	NotPrincipal json.RawMessage `json:"NotPrincipal,omitempty"`
	Condition    json.RawMessage `json:"Condition,omitempty"`
}

// normalizeStatements handles both single statement and array of statements.
func normalizeStatements(raw json.RawMessage) ([]*Statement, error) {
	if raw == nil {
		return nil, nil
	}

	var stmts []rawStatement
	if err := json.Unmarshal(raw, &stmts); err == nil {
		return parseStatements(stmts)
	}

	var stmt rawStatement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("failed to parse statements: %w", err)
	}

	return parseStatements([]rawStatement{stmt})
}

func parseStatements(rawStmts []rawStatement) ([]*Statement, error) {
	var statements []*Statement

	for _, raw := range rawStmts {
		stmt := &Statement{
			SID:    raw.SID,
			Effect: raw.Effect,
		}

		if raw.Action != nil {
			actions, err := normalizeStringOrArray(raw.Action)
			if err != nil {
				return nil, fmt.Errorf("failed to parse Action: %w", err)
			}
			stmt.Actions = actions
		}

		if raw.NotAction != nil {
			notActions, err := normalizeStringOrArray(raw.NotAction)
			if err != nil {
				return nil, fmt.Errorf("failed to parse NotAction: %w", err)
			}
			stmt.NotActions = notActions
		}

		if raw.Resource != nil {
			resources, err := normalizeStringOrArray(raw.Resource)
			if err != nil {
				return nil, fmt.Errorf("failed to parse Resource: %w", err)
			}
			stmt.Resources = resources
		}

		if raw.NotResource != nil {
			notResources, err := normalizeStringOrArray(raw.NotResource)
			if err != nil {
				return nil, fmt.Errorf("failed to parse NotResource: %w", err)
			}
			stmt.NotResources = notResources
			stmt.HasNotResource = true
		}

		if raw.Principal != nil {
			principals, err := parsePrincipals(raw.Principal)
			if err != nil {
				return nil, fmt.Errorf("failed to parse Principal: %w", err)
			}
			stmt.Principals = principals
		}

		if raw.NotPrincipal != nil {
			notPrincipals, err := parsePrincipals(raw.NotPrincipal)
			if err != nil {
				return nil, fmt.Errorf("failed to parse NotPrincipal: %w", err)
			}
			stmt.NotPrincipals = notPrincipals
			stmt.HasNotPrincipal = true
		}

		if raw.Condition != nil {
			conditions, err := parseConditions(raw.Condition)
			if err != nil {
				return nil, fmt.Errorf("failed to parse Condition: %w", err)
			}
			recognized, unrecognized := classifyConditions(conditions)
			stmt.Conditions = recognized
			stmt.UnrecognizedConditions = unrecognized
		}

		statements = append(statements, stmt)
	}

	return statements, nil
}

// normalizeStringOrArray handles AWS policy fields that can be string or []string.
func normalizeStringOrArray(raw json.RawMessage) ([]string, error) {
	if raw == nil {
		return nil, nil
	}

	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return []string{str}, nil
	}

	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, err
	}
	return arr, nil
}

// parsePrincipals handles the Principal field which can be:
// - "*" (string)
// - {"AWS": "arn:..."} (object with string value)
// - {"AWS": ["arn:...", "arn:..."]} (object with array value)
// - {"Service": "..."} (service principal)
func parsePrincipals(raw json.RawMessage) ([]Principal, error) {
	if raw == nil {
		return nil, nil
	}

	var star string
	if err := json.Unmarshal(raw, &star); err == nil {
		if star == "*" {
			return []Principal{{Type: "*", Value: "*"}}, nil
		}
		// Single ARN string (rare but valid)
		return []Principal{{Type: "AWS", Value: star}}, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}

	var principals []Principal
	for pType, pVal := range obj {
		values, err := normalizeStringOrArray(pVal)
		if err != nil {
			return nil, err
		}
		for _, v := range values {
			principals = append(principals, Principal{Type: pType, Value: v})
		}
	}

	return principals, nil
}

// parseConditions parses the Condition block.
// Structure: {"Operator": {"Key": "Value" or ["Values"]}}
func parseConditions(raw json.RawMessage) ([]Condition, error) {
	if raw == nil {
		return nil, nil
	}

	var condObj map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &condObj); err != nil {
		return nil, err
	}

	var conditions []Condition
	for operator, keys := range condObj {
		for key, valRaw := range keys {
			values, err := normalizeStringOrArray(valRaw)
			if err != nil {
				return nil, err
			}
			conditions = append(conditions, Condition{
				Operator: operator,
				Key:      key,
				Values:   values,
			})
		}
	}

	return conditions, nil
}

// classifyConditions splits conditions into recognized and unrecognized.
//
// Recognized means the verifier fully models the condition's semantics:
//   - StringNotEquals / aws:sourceVpce  → VPCE-deny (deny unless request comes via VPCE)
//   - StringEquals    / aws:PrincipalTag/* → ABAC allow (allow when principal tag matches)
//
// Any other operator/key combination is unrecognized: the condition is dropped
// and the statement is approximated, which may over- or under-grant access.
func classifyConditions(conditions []Condition) (recognized, unrecognized []Condition) {
	for _, c := range conditions {
		key := strings.ToLower(c.Key)
		op := strings.ToLower(c.Operator)
		switch {
		case key == "aws:sourcevpce" && op == "stringnotequals":
			recognized = append(recognized, c)
		case strings.HasPrefix(key, "aws:principaltag/") && op == "stringequals":
			recognized = append(recognized, c)
		default:
			unrecognized = append(unrecognized, c)
		}
	}
	return
}

// IsAllow returns true if this is an Allow statement.
func (s *Statement) IsAllow() bool {
	return strings.EqualFold(s.Effect, "Allow")
}

// IsDeny returns true if this is a Deny statement.
func (s *Statement) IsDeny() bool {
	return strings.EqualFold(s.Effect, "Deny")
}

// HasConditionKey checks if the statement has a condition with the given key.
func (s *Statement) HasConditionKey(key string) bool {
	for _, c := range s.Conditions {
		if strings.EqualFold(c.Key, key) {
			return true
		}
	}
	return false
}

// GetConditionValues returns values for a specific condition key.
func (s *Statement) GetConditionValues(key string) []string {
	for _, c := range s.Conditions {
		if strings.EqualFold(c.Key, key) {
			return c.Values
		}
	}
	return nil
}

// HasVPCECondition returns true if the statement has an aws:sourceVpce condition.
func (s *Statement) HasVPCECondition() bool {
	return s.HasConditionKey("aws:sourceVpce") || s.HasConditionKey("aws:SourceVpce")
}

// GetVPCEOperator returns the condition operator used for the aws:sourceVpce key,
// or "" if no such condition exists.
func (s *Statement) GetVPCEOperator() string {
	for _, c := range s.Conditions {
		if strings.EqualFold(c.Key, "aws:sourceVpce") {
			return c.Operator
		}
	}
	return ""
}

// GetABACOperator returns the condition operator used for the first aws:PrincipalTag key,
// or "" if no such condition exists.
func (s *Statement) GetABACOperator() string {
	for _, c := range s.Conditions {
		if strings.HasPrefix(strings.ToLower(c.Key), "aws:principaltag/") {
			return c.Operator
		}
	}
	return ""
}

// GetVPCEID returns the VPCE ID from the condition, if present.
func (s *Statement) GetVPCEID() string {
	values := s.GetConditionValues("aws:sourceVpce")
	if len(values) == 0 {
		values = s.GetConditionValues("aws:SourceVpce")
	}
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

// HasABACCondition returns true if the statement has a PrincipalTag condition.
func (s *Statement) HasABACCondition() bool {
	for _, c := range s.Conditions {
		if strings.HasPrefix(c.Key, "aws:PrincipalTag/") ||
			strings.HasPrefix(c.Key, "aws:principalTag/") {
			return true
		}
	}
	return false
}

// GetServicePrincipals returns AWS service principal names from the statement (e.g. "lambda.amazonaws.com").
func (s *Statement) GetServicePrincipals() []string {
	var svcs []string
	for _, p := range s.Principals {
		if p.Type == "Service" {
			svcs = append(svcs, p.Value)
		}
	}
	return svcs
}

// GetPrincipalARNs returns AWS principal ARNs from the statement.
func (s *Statement) GetPrincipalARNs() []string {
	var arns []string
	for _, p := range s.Principals {
		if p.Type == "AWS" && p.Value != "*" {
			arns = append(arns, p.Value)
		}
	}
	return arns
}

func (s *Statement) HasWildcardPrincipal() bool {
	for _, p := range s.Principals {
		if p.Value == "*" {
			return true
		}
	}
	return false
}

func (s *Statement) HasBucketLevelResource() bool {
	for _, r := range s.Resources {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if r == "*" {
			return true
		}
		// bucket ARN, not object ARN
		if !strings.Contains(r, "/*") {
			return true
		}
	}
	return false
}

func (s *Statement) HasObjectLevelResource() bool {
	for _, r := range s.Resources {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if r == "*" {
			return true
		}
		if strings.Contains(r, "/*") {
			return true
		}
	}
	return false
}

// GetDenyStatements returns all Deny statements.
func (d *IAMPolicyDocument) GetDenyStatements() []*Statement {
	var stmts []*Statement
	for _, s := range d.Statements {
		if s.IsDeny() {
			stmts = append(stmts, s)
		}
	}
	return stmts
}

// GetAllowStatements returns all Allow statements.
func (d *IAMPolicyDocument) GetAllowStatements() []*Statement {
	var stmts []*Statement
	for _, s := range d.Statements {
		if s.IsAllow() {
			stmts = append(stmts, s)
		}
	}
	return stmts
}

// GetAllActions returns all actions from Allow statements.
func (d *IAMPolicyDocument) GetAllActions() []string {
	seen := make(map[string]bool)
	var actions []string
	for _, s := range d.GetAllowStatements() {
		for _, a := range s.Actions {
			if !seen[a] {
				seen[a] = true
				actions = append(actions, a)
			}
		}
	}
	return actions
}

// extractS3BucketFromResource extracts the S3 bucket name from a resource ARN.
// Returns "*" for wildcard resources, "" for non-S3 resources.
func extractS3BucketFromResource(resource string) string {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return ""
	}
	if resource == "*" {
		return "*"
	}

	base := strings.TrimSuffix(resource, "/*")
	if strings.HasPrefix(base, "arn:aws") {
		parts := strings.Split(base, ":::")
		if len(parts) == 2 && (strings.HasPrefix(parts[0], "arn:aws") && strings.Contains(parts[0], ":s3")) {
			name := parts[1]
			if name == "" || name == "*" {
				return "*"
			}
			return name
		}
		return ""
	}
	return ""
}

func (d *IAMPolicyDocument) GetAllowActionsPerBucket() map[string][]string {
	result := make(map[string][]string)
	seen := make(map[string]map[string]bool)

	for _, stmt := range d.Statements {
		if !stmt.IsAllow() || len(stmt.Actions) == 0 {
			continue
		}

		buckets := make(map[string]bool)
		for _, r := range stmt.Resources {
			if name := extractS3BucketFromResource(r); name != "" {
				buckets[name] = true
			}
		}

		if len(stmt.Resources) == 0 {
			buckets["*"] = true
		}

		if buckets["*"] {
			buckets = map[string]bool{"*": true}
		}

		for bucket := range buckets {
			if seen[bucket] == nil {
				seen[bucket] = make(map[string]bool)
			}
			for _, a := range stmt.Actions {
				if !seen[bucket][a] {
					seen[bucket][a] = true
					result[bucket] = append(result[bucket], a)
				}
			}
		}
	}

	return result
}

// GetDeniedActions returns all actions from Deny statements.
func (d *IAMPolicyDocument) GetDeniedActions() []string {
	seen := make(map[string]bool)
	var actions []string
	for _, s := range d.GetDenyStatements() {
		for _, a := range s.Actions {
			if !seen[a] {
				seen[a] = true
				actions = append(actions, a)
			}
		}
	}
	return actions
}
