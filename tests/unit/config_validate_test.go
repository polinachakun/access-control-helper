package unit_test

import (
	"strings"
	"testing"

	"access-control-helper/internal/ir"
)

func TestValidate_EmptyConfig_TwoFatalErrors(t *testing.T) {
	c := &ir.Config{}
	errs := c.Validate()

	fatal := fatalErrors(errs)
	if len(fatal) != 2 {
		t.Fatalf("expected 2 fatal errors, got %d: %v", len(fatal), errs)
	}
}

func TestValidate_NoBuckets_FatalError(t *testing.T) {
	c := &ir.Config{
		Roles: []*ir.IAMRole{{TFName: "app_role"}},
	}
	errs := c.Validate()

	fatal := fatalErrors(errs)
	if len(fatal) != 1 {
		t.Fatalf("expected 1 fatal error (no buckets), got %d: %v", len(fatal), errs)
	}
	if !strings.Contains(fatal[0].Message, "bucket") {
		t.Errorf("error message should mention buckets, got: %q", fatal[0].Message)
	}
}

func TestValidate_NoRoles_FatalError(t *testing.T) {
	c := &ir.Config{
		Buckets: []*ir.S3Bucket{{TFName: "my_bucket"}},
	}
	errs := c.Validate()

	fatal := fatalErrors(errs)
	if len(fatal) != 1 {
		t.Fatalf("expected 1 fatal error (no roles), got %d: %v", len(fatal), errs)
	}
	if !strings.Contains(fatal[0].Message, "role") {
		t.Errorf("error message should mention roles, got: %q", fatal[0].Message)
	}
}

func TestValidate_ValidConfig_NoErrors(t *testing.T) {
	c := &ir.Config{
		Buckets: []*ir.S3Bucket{{TFName: "my_bucket"}},
		Roles:   []*ir.IAMRole{{TFName: "app_role"}},
	}
	errs := c.Validate()
	if len(errs) != 0 {
		t.Errorf("expected no validation errors, got: %v", errs)
	}
}

func TestValidate_UnattachedBucketPolicy_NonFatalWarning(t *testing.T) {
	c := &ir.Config{
		Buckets: []*ir.S3Bucket{{TFName: "my_bucket"}},
		Roles:   []*ir.IAMRole{{TFName: "app_role"}},
		BucketPolicies: []*ir.BucketPolicy{
			{TFName: "orphan_policy", BucketRef: "", AllowAnyPrincipal: true, AllowActions: []string{"s3:GetObject"}},
		},
	}
	errs := c.Validate()

	fatal := fatalErrors(errs)
	if len(fatal) != 0 {
		t.Errorf("unattached bucket policy should not be fatal, got fatal: %v", fatal)
	}
	warnings := nonFatalErrors(errs)
	if len(warnings) == 0 {
		t.Error("expected a non-fatal warning for unattached bucket policy")
	}
	if !strings.Contains(warnings[0].Message, "orphan_policy") {
		t.Errorf("warning should name the offending policy, got: %q", warnings[0].Message)
	}
}

func TestValidate_EmptyActionsBucketPolicy_NonFatalWarning(t *testing.T) {
	c := &ir.Config{
		Buckets: []*ir.S3Bucket{{TFName: "my_bucket"}},
		Roles:   []*ir.IAMRole{{TFName: "app_role"}},
		BucketPolicies: []*ir.BucketPolicy{
			{
				TFName:    "empty_policy",
				BucketRef: "aws_s3_bucket.my_bucket",
				// no AllowActions, no DenyActions, no VPCE, no AnyPrincipal
			},
		},
	}
	errs := c.Validate()

	fatal := fatalErrors(errs)
	if len(fatal) != 0 {
		t.Errorf("empty-actions bucket policy should not be fatal, got fatal: %v", fatal)
	}
	warnings := nonFatalErrors(errs)
	if len(warnings) == 0 {
		t.Error("expected a non-fatal warning for bucket policy with no actions")
	}
	if !strings.Contains(warnings[0].Message, "empty_policy") {
		t.Errorf("warning should name the offending policy, got: %q", warnings[0].Message)
	}
}

func TestValidate_VPCEPolicyWithNoActions_NotWarned(t *testing.T) {
	// A VPCE deny policy has no AllowActions but is valid — should not warn about no actions.
	c := &ir.Config{
		Buckets: []*ir.S3Bucket{{TFName: "my_bucket"}},
		Roles:   []*ir.IAMRole{{TFName: "app_role"}},
		BucketPolicies: []*ir.BucketPolicy{
			{
				TFName:     "vpce_policy",
				BucketRef:  "aws_s3_bucket.my_bucket",
				DenyVpceID: "vpce-12345",
			},
		},
	}
	errs := c.Validate()
	if len(errs) != 0 {
		t.Errorf("VPCE policy with no actions should not produce warnings, got: %v", errs)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func fatalErrors(errs []ir.ValidationError) []ir.ValidationError {
	var out []ir.ValidationError
	for _, e := range errs {
		if e.Fatal {
			out = append(out, e)
		}
	}
	return out
}

func nonFatalErrors(errs []ir.ValidationError) []ir.ValidationError {
	var out []ir.ValidationError
	for _, e := range errs {
		if !e.Fatal {
			out = append(out, e)
		}
	}
	return out
}
