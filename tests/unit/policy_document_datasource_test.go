package unit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"access-control-helper/internal/ir"
	"access-control-helper/internal/parser"
	"access-control-helper/internal/resolver"
)

// parseTFString runs the full parser → resolver → IR builder pipeline on an
// inline HCL string and returns the resulting Config.
func parseTFString(t *testing.T, hclContent string) (*ir.Config, []string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	if err := os.WriteFile(path, []byte(hclContent), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	p := parser.NewParser()
	result, err := p.ParseFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	res := resolver.NewResolver()
	resources, err := res.Resolve(result)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	config, builderWarnings, err := ir.BuildFromResources(resources, res.GetGraph())
	if err != nil {
		t.Fatalf("BuildFromResources: %v", err)
	}
	return config, append(res.Warnings(), builderWarnings...)
}

func TestPolicyDocumentDataSource_BucketPolicy_Allow(t *testing.T) {
	hcl := `
resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"
  tags   = { environment = "prod" }
}

data "aws_iam_policy_document" "allow_read" {
  statement {
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      "arn:aws:s3:::my-bucket",
      "arn:aws:s3:::my-bucket/*",
    ]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/app-role"]
    }
  }
}

resource "aws_s3_bucket_policy" "policy" {
  bucket = aws_s3_bucket.my_bucket.id
  policy = data.aws_iam_policy_document.allow_read.json
}
`
	config, warnings := parseTFString(t, hcl)

	for _, w := range warnings {
		if strings.Contains(w, "unresolved") || strings.Contains(w, "skipped") {
			t.Errorf("unexpected warning about unresolved policy: %s", w)
		}
	}

	if len(config.BucketPolicies) == 0 {
		t.Fatal("expected at least one BucketPolicy, got none — data source was not resolved")
	}

	bp := config.BucketPolicies[0]

	found := false
	for _, a := range bp.AllowActions {
		if a == "s3:GetObject" {
			found = true
		}
	}
	if !found {
		t.Errorf("s3:GetObject not in AllowActions %v — policy document was not synthesized", bp.AllowActions)
	}

	if bp.AllowAnyPrincipal {
		t.Error("AllowAnyPrincipal should be false — only a specific ARN principal is set")
	}
	if len(bp.AllowPrincipals) == 0 {
		t.Error("AllowPrincipals should contain the ARN from the principals block")
	}
}

func TestPolicyDocumentDataSource_BucketPolicy_Deny(t *testing.T) {
	hcl := `
resource "aws_s3_bucket" "vault" {
  bucket = "vault-bucket"
  tags   = { environment = "prod" }
}

data "aws_iam_policy_document" "deny_delete" {
  statement {
    effect    = "Deny"
    actions   = ["s3:DeleteObject"]
    resources = ["arn:aws:s3:::vault-bucket/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "vault_policy" {
  bucket = aws_s3_bucket.vault.id
  policy = data.aws_iam_policy_document.deny_delete.json
}
`
	config, warnings := parseTFString(t, hcl)

	for _, w := range warnings {
		if strings.Contains(w, "unresolved") || strings.Contains(w, "skipped") {
			t.Errorf("unexpected warning: %s", w)
		}
	}

	if len(config.BucketPolicies) == 0 {
		t.Fatal("expected at least one BucketPolicy — data source deny not resolved")
	}

	bp := config.BucketPolicies[0]
	found := false
	for _, a := range bp.DenyActions {
		if a == "s3:DeleteObject" {
			found = true
		}
	}
	if !found {
		t.Errorf("s3:DeleteObject not in DenyActions %v", bp.DenyActions)
	}
	if !bp.DenyAnyPrincipal {
		t.Error("DenyAnyPrincipal should be true — wildcard principal in Deny statement")
	}
}

func TestPolicyDocumentDataSource_WithCondition(t *testing.T) {
	hcl := `
resource "aws_s3_bucket" "secure" {
  bucket = "secure-bucket"
  tags   = { environment = "prod" }
}

data "aws_iam_policy_document" "vpce_deny" {
  statement {
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::secure-bucket/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "aws:sourceVpce"
      values   = ["vpce-0a1b2c3d"]
    }
  }
}

resource "aws_s3_bucket_policy" "secure_policy" {
  bucket = aws_s3_bucket.secure.id
  policy = data.aws_iam_policy_document.vpce_deny.json
}
`
	config, warnings := parseTFString(t, hcl)

	for _, w := range warnings {
		if strings.Contains(w, "unresolved") || strings.Contains(w, "skipped") {
			t.Errorf("unexpected warning: %s", w)
		}
	}

	if len(config.BucketPolicies) == 0 {
		t.Fatal("expected bucket policy from data source with condition")
	}

	bp := config.BucketPolicies[0]
	if bp.DenyVpceID == "" {
		t.Errorf("DenyVpceID should be populated from condition block, got empty")
	}
	if bp.DenyVpceID != "vpce-0a1b2c3d" {
		t.Errorf("DenyVpceID = %q, want vpce-0a1b2c3d", bp.DenyVpceID)
	}
}

func TestPolicyDocumentDataSource_IAMRolePolicy(t *testing.T) {
	hcl := `
resource "aws_iam_role" "worker" {
  name = "worker-role"
  assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"}}]}"
  tags = { environment = "prod" }
}

data "aws_iam_policy_document" "worker_policy" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}

resource "aws_iam_role_policy" "worker_inline" {
  role   = aws_iam_role.worker.id
  policy = data.aws_iam_policy_document.worker_policy.json
}
`
	config, warnings := parseTFString(t, hcl)

	for _, w := range warnings {
		if strings.Contains(w, "unresolved") || strings.Contains(w, "skipped") {
			t.Errorf("unexpected warning: %s", w)
		}
	}

	role := config.GetRoleByTFName("worker")
	if role == nil {
		t.Fatal("role 'worker' not found")
	}
	if !role.HasRolePolicy {
		t.Error("HasRolePolicy should be true — role_policy references data source")
	}

	actions := make(map[string]bool)
	for _, a := range role.RolePolicyActions {
		actions[a] = true
	}
	if !actions["s3:GetObject"] {
		t.Errorf("s3:GetObject not in role policy actions %v", role.RolePolicyActions)
	}
	if !actions["s3:PutObject"] {
		t.Errorf("s3:PutObject not in role policy actions %v", role.RolePolicyActions)
	}
}

func TestPolicyDocumentDataSource_NotActions(t *testing.T) {
	hcl := `
resource "aws_s3_bucket" "bucket" {
  bucket = "test-bucket"
  tags   = { environment = "prod" }
}

data "aws_iam_policy_document" "restricted" {
  statement {
    effect      = "Allow"
    not_actions = ["s3:DeleteObject", "s3:DeleteBucket"]
    resources   = ["arn:aws:s3:::test-bucket/*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/app"]
    }
  }
}

resource "aws_s3_bucket_policy" "p" {
  bucket = aws_s3_bucket.bucket.id
  policy = data.aws_iam_policy_document.restricted.json
}
`
	config, _ := parseTFString(t, hcl)

	if len(config.BucketPolicies) == 0 {
		t.Fatal("expected bucket policy")
	}

	bp := config.BucketPolicies[0]
	if !bp.HasAllowNotAction {
		t.Error("HasAllowNotAction should be true for NotAction statement")
	}
	found := false
	for _, a := range bp.AllowNotActions {
		if a == "s3:DeleteObject" {
			found = true
		}
	}
	if !found {
		t.Errorf("s3:DeleteObject should be in AllowNotActions, got %v", bp.AllowNotActions)
	}
}

func TestPolicyDocumentDataSource_DynamicBlock_Warning(t *testing.T) {
	hcl := `
resource "aws_s3_bucket" "bucket" {
  bucket = "test-bucket"
  tags   = { environment = "prod" }
}

data "aws_iam_policy_document" "mixed" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::test-bucket/*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/reader"]
    }
  }

  dynamic "statement" {
    for_each = var.extra_statements
    content {
      effect    = statement.value.effect
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }
}

resource "aws_s3_bucket_policy" "p" {
  bucket = aws_s3_bucket.bucket.id
  policy = data.aws_iam_policy_document.mixed.json
}
`
	config, warnings := parseTFString(t, hcl)

	// The static statement must still be resolved.
	if len(config.BucketPolicies) == 0 {
		t.Fatal("expected bucket policy — static statement should be preserved")
	}
	found := false
	for _, a := range config.BucketPolicies[0].AllowActions {
		if a == "s3:GetObject" {
			found = true
		}
	}
	if !found {
		t.Errorf("static s3:GetObject statement lost; AllowActions = %v", config.BucketPolicies[0].AllowActions)
	}

	// A warning must be emitted for the dynamic block.
	warnFound := false
	for _, w := range warnings {
		if strings.Contains(w, "dynamic") && strings.Contains(w, "statement") {
			warnFound = true
		}
	}
	if !warnFound {
		t.Errorf("expected a warning about dynamic statement block, got warnings: %v", warnings)
	}
}
