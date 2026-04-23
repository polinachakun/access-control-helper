package unit_test

import (
	"strings"
	"testing"

	"access-control-helper/internal/ir"
)

func TestParsePolicyDocument_Empty(t *testing.T) {
	doc, err := ir.ParsePolicyDocument("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc != nil {
		t.Fatalf("expected nil for empty input, got %+v", doc)
	}
}

func TestParsePolicyDocument_MalformedJSON(t *testing.T) {
	_, err := ir.ParsePolicyDocument(`{not valid json`)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestParsePolicyDocument_SingleStatementObject(t *testing.T) {
	raw := `{
		"Version": "2012-10-17",
		"Statement": {
			"Effect": "Allow",
			"Action": "s3:GetObject",
			"Resource": "*"
		}
	}`
	doc, err := ir.ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(doc.Statements))
	}
	s := doc.Statements[0]
	if s.Effect != "Allow" {
		t.Errorf("Effect = %q, want %q", s.Effect, "Allow")
	}
	if len(s.Actions) != 1 || s.Actions[0] != "s3:GetObject" {
		t.Errorf("Actions = %v, want [s3:GetObject]", s.Actions)
	}
}

func TestParsePolicyDocument_ArrayOfStatements(t *testing.T) {
	raw := `{
		"Version": "2012-10-17",
		"Statement": [
			{"Effect": "Allow",  "Action": "s3:GetObject",    "Resource": "*"},
			{"Effect": "Deny",   "Action": "s3:DeleteObject", "Resource": "*"}
		]
	}`
	doc, err := ir.ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(doc.Statements))
	}
	if doc.Statements[0].Effect != "Allow" {
		t.Errorf("statement 0 Effect = %q, want Allow", doc.Statements[0].Effect)
	}
	if doc.Statements[1].Effect != "Deny" {
		t.Errorf("statement 1 Effect = %q, want Deny", doc.Statements[1].Effect)
	}
}

func TestParsePolicyDocument_ActionAsString(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}}`
	doc, err := ir.ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Statements[0].Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(doc.Statements[0].Actions))
	}
	if doc.Statements[0].Actions[0] != "s3:PutObject" {
		t.Errorf("Action = %q, want s3:PutObject", doc.Statements[0].Actions[0])
	}
}

func TestParsePolicyDocument_ActionAsArray(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}}`
	doc, err := ir.ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	actions := doc.Statements[0].Actions
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}
	if actions[0] != "s3:GetObject" || actions[1] != "s3:ListBucket" {
		t.Errorf("actions = %v, want [s3:GetObject s3:ListBucket]", actions)
	}
}

func TestParsePolicyDocument_PrincipalWildcard(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:*","Resource":"*","Principal":"*"}}`
	doc, err := ir.ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !doc.Statements[0].HasWildcardPrincipal() {
		t.Error("expected wildcard principal")
	}
}

func TestParsePolicyDocument_PrincipalAWSString(t *testing.T) {
	raw := `{
		"Version":"2012-10-17",
		"Statement":{
			"Effect":"Allow",
			"Action":"s3:GetObject",
			"Resource":"*",
			"Principal":{"AWS":"arn:aws:iam::123456789012:role/my-role"}
		}
	}`
	doc, err := ir.ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	arns := doc.Statements[0].GetPrincipalARNs()
	if len(arns) != 1 || arns[0] != "arn:aws:iam::123456789012:role/my-role" {
		t.Errorf("principal ARNs = %v, want one ARN", arns)
	}
}

func TestParsePolicyDocument_PrincipalAWSArray(t *testing.T) {
	raw := `{
		"Version":"2012-10-17",
		"Statement":{
			"Effect":"Allow",
			"Action":"s3:GetObject",
			"Resource":"*",
			"Principal":{"AWS":["arn:aws:iam::111:role/roleA","arn:aws:iam::111:role/roleB"]}
		}
	}`
	doc, err := ir.ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Statements[0].GetPrincipalARNs()) != 2 {
		t.Errorf("expected 2 principal ARNs, got %d", len(doc.Statements[0].GetPrincipalARNs()))
	}
}

func TestParsePolicyDocument_ConditionParsed(t *testing.T) {
	raw := `{
		"Version":"2012-10-17",
		"Statement":{
			"Effect":"Deny",
			"Action":"s3:*",
			"Resource":"*",
			"Principal":"*",
			"Condition":{
				"StringNotEquals":{"aws:sourceVpce":"vpce-0abc1234"}
			}
		}
	}`
	doc, err := ir.ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := doc.Statements[0]
	if len(s.Conditions) == 0 {
		t.Fatal("expected conditions, got none")
	}
	c := s.Conditions[0]
	if c.Operator != "StringNotEquals" {
		t.Errorf("Operator = %q, want StringNotEquals", c.Operator)
	}
	if c.Key != "aws:sourceVpce" {
		t.Errorf("Key = %q, want aws:sourceVpce", c.Key)
	}
	if len(c.Values) != 1 || c.Values[0] != "vpce-0abc1234" {
		t.Errorf("Values = %v, want [vpce-0abc1234]", c.Values)
	}
}

func TestParsePolicyDocument_NotActionField(t *testing.T) {
	raw := `{
		"Version":"2012-10-17",
		"Statement":{
			"Effect":"Allow",
			"NotAction":["s3:DeleteObject"],
			"Resource":"*"
		}
	}`
	doc, err := ir.ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := doc.Statements[0]
	if len(s.NotActions) != 1 || s.NotActions[0] != "s3:DeleteObject" {
		t.Errorf("NotActions = %v, want [s3:DeleteObject]", s.NotActions)
	}
	if len(s.Actions) != 0 {
		t.Errorf("Actions should be empty when NotAction is set, got %v", s.Actions)
	}
}

func TestParsePolicyDocument_VersionPreserved(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[]}`
	doc, err := ir.ParsePolicyDocument(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if doc.Version != "2012-10-17" {
		t.Errorf("Version = %q, want 2012-10-17", doc.Version)
	}
}

func TestStatement_IsAllow(t *testing.T) {
	allow := &ir.Statement{Effect: "Allow"}
	deny := &ir.Statement{Effect: "Deny"}
	if !allow.IsAllow() {
		t.Error("Allow statement IsAllow() = false")
	}
	if allow.IsDeny() {
		t.Error("Allow statement IsDeny() = true")
	}
	if deny.IsAllow() {
		t.Error("Deny statement IsAllow() = true")
	}
	if !deny.IsDeny() {
		t.Error("Deny statement IsDeny() = false")
	}
}

func TestStatement_IsAllow_CaseInsensitive(t *testing.T) {
	if !(&ir.Statement{Effect: "ALLOW"}).IsAllow() {
		t.Error("uppercase ALLOW should match IsAllow")
	}
}

func TestStatement_HasVPCECondition(t *testing.T) {
	s := &ir.Statement{
		Conditions: []ir.Condition{
			{Operator: "StringNotEquals", Key: "aws:sourceVpce", Values: []string{"vpce-abc"}},
		},
	}
	if !s.HasVPCECondition() {
		t.Error("expected HasVPCECondition = true")
	}
	if s.GetVPCEID() != "vpce-abc" {
		t.Errorf("GetVPCEID() = %q, want vpce-abc", s.GetVPCEID())
	}
}

func TestStatement_NoVPCECondition(t *testing.T) {
	s := &ir.Statement{
		Conditions: []ir.Condition{
			{Operator: "StringEquals", Key: "aws:PrincipalTag/environment", Values: []string{"prod"}},
		},
	}
	if s.HasVPCECondition() {
		t.Error("expected HasVPCECondition = false")
	}
	if s.GetVPCEID() != "" {
		t.Errorf("GetVPCEID() = %q, want empty", s.GetVPCEID())
	}
}

func TestStatement_HasABACCondition(t *testing.T) {
	s := &ir.Statement{
		Conditions: []ir.Condition{
			{Operator: "StringEquals", Key: "aws:PrincipalTag/environment", Values: []string{"prod"}},
		},
	}
	if !s.HasABACCondition() {
		t.Error("expected HasABACCondition = true for PrincipalTag condition")
	}
}

func TestStatement_NoABACCondition(t *testing.T) {
	s := &ir.Statement{
		Conditions: []ir.Condition{
			{Operator: "StringEquals", Key: "aws:sourceVpce", Values: []string{"vpce-abc"}},
		},
	}
	if s.HasABACCondition() {
		t.Error("expected HasABACCondition = false for non-PrincipalTag condition")
	}
}

func TestStatement_HasWildcardPrincipal(t *testing.T) {
	s := &ir.Statement{Principals: []ir.Principal{{Type: "*", Value: "*"}}}
	if !s.HasWildcardPrincipal() {
		t.Error("expected HasWildcardPrincipal = true")
	}
}

func TestStatement_GetPrincipalARNs(t *testing.T) {
	s := &ir.Statement{
		Principals: []ir.Principal{
			{Type: "AWS", Value: "arn:aws:iam::123:role/r1"},
			{Type: "*", Value: "*"},
			{Type: "AWS", Value: "arn:aws:iam::123:role/r2"},
		},
	}
	arns := s.GetPrincipalARNs()
	if len(arns) != 2 {
		t.Fatalf("expected 2 ARNs, got %d: %v", len(arns), arns)
	}
}

func TestStatement_HasBucketLevelResource(t *testing.T) {
	bucket := &ir.Statement{Resources: []string{"arn:aws:s3:::my-bucket"}}
	object := &ir.Statement{Resources: []string{"arn:aws:s3:::my-bucket/*"}}
	both := &ir.Statement{Resources: []string{"arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"}}
	star := &ir.Statement{Resources: []string{"*"}}

	if !bucket.HasBucketLevelResource() {
		t.Error("bucket ARN: HasBucketLevelResource = false")
	}
	if bucket.HasObjectLevelResource() {
		t.Error("pure bucket ARN: HasObjectLevelResource = true")
	}
	if !object.HasObjectLevelResource() {
		t.Error("object ARN: HasObjectLevelResource = false")
	}
	if !both.HasBucketLevelResource() || !both.HasObjectLevelResource() {
		t.Error("both ARNs: expected both resource flags true")
	}
	if !star.HasBucketLevelResource() || !star.HasObjectLevelResource() {
		t.Error("wildcard *: expected both resource flags true")
	}
}

func TestDocument_GetAllowAndDenyStatements(t *testing.T) {
	doc := &ir.IAMPolicyDocument{
		Statements: []*ir.Statement{
			{Effect: "Allow", Actions: []string{"s3:GetObject"}},
			{Effect: "Deny", Actions: []string{"s3:DeleteObject"}},
			{Effect: "Allow", Actions: []string{"s3:PutObject"}},
		},
	}
	if len(doc.GetAllowStatements()) != 2 {
		t.Errorf("expected 2 allow statements, got %d", len(doc.GetAllowStatements()))
	}
	if len(doc.GetDenyStatements()) != 1 {
		t.Errorf("expected 1 deny statement, got %d", len(doc.GetDenyStatements()))
	}
}

func TestDocument_GetAllActions_Deduplicates(t *testing.T) {
	doc := &ir.IAMPolicyDocument{
		Statements: []*ir.Statement{
			{Effect: "Allow", Actions: []string{"s3:GetObject", "s3:PutObject"}},
			{Effect: "Allow", Actions: []string{"s3:GetObject", "s3:ListBucket"}},
		},
	}
	if len(doc.GetAllActions()) != 3 {
		t.Errorf("expected 3 unique actions, got %d: %v", len(doc.GetAllActions()), doc.GetAllActions())
	}
}

func TestDocument_GetDeniedActions(t *testing.T) {
	doc := &ir.IAMPolicyDocument{
		Statements: []*ir.Statement{
			{Effect: "Allow", Actions: []string{"s3:GetObject"}},
			{Effect: "Deny", Actions: []string{"s3:DeleteObject", "s3:PutObject"}},
		},
	}
	denied := doc.GetDeniedActions()
	if len(denied) != 2 {
		t.Errorf("expected 2 denied actions, got %d: %v", len(denied), denied)
	}
	for _, a := range denied {
		if !strings.HasPrefix(a, "s3:") {
			t.Errorf("unexpected denied action: %q", a)
		}
	}
}

func TestDocument_GetAllActions_IgnoresDeny(t *testing.T) {
	doc := &ir.IAMPolicyDocument{
		Statements: []*ir.Statement{
			{Effect: "Deny", Actions: []string{"s3:DeleteObject"}},
		},
	}
	if len(doc.GetAllActions()) != 0 {
		t.Errorf("GetAllActions should ignore Deny statements, got %v", doc.GetAllActions())
	}
}

func TestStatement_GetConditionValues(t *testing.T) {
	s := &ir.Statement{
		Conditions: []ir.Condition{
			{Operator: "StringEquals", Key: "aws:PrincipalTag/environment", Values: []string{"prod", "staging"}},
		},
	}
	vals := s.GetConditionValues("aws:PrincipalTag/environment")
	if len(vals) != 2 {
		t.Errorf("expected 2 values, got %v", vals)
	}
	if s.GetConditionValues("nonexistent") != nil {
		t.Error("nonexistent key should return nil")
	}
}

func TestStatement_HasConditionKey_CaseInsensitive(t *testing.T) {
	s := &ir.Statement{
		Conditions: []ir.Condition{
			{Key: "aws:sourceVpce", Values: []string{"vpce-abc"}},
		},
	}
	if !s.HasConditionKey("AWS:SOURCEVPCE") {
		t.Error("HasConditionKey should be case insensitive")
	}
}
