package unit_test

import (
	"testing"

	"access-control-helper/internal/parser"
)

func TestIsSecurityRelevant_ACLTypesAreSecurityRelevant(t *testing.T) {
	// These types influence access control and must NOT be suppressed.
	securityRelevant := []string{
		"aws_s3_bucket_acl",
		"aws_s3_object_acl",
		"aws_s3_bucket_ownership_controls",
	}
	for _, rt := range securityRelevant {
		if !parser.IsSecurityRelevantResourceType(rt) {
			t.Errorf("IsSecurityRelevantResourceType(%q) = false, want true (ACL/ownership types affect authorization)", rt)
		}
	}
}

func TestIsSecurityRelevant_OperationalTypesAreNotSecurityRelevant(t *testing.T) {
	// These S3 types match the aws_s3_ prefix but do not affect authorization.
	// aws_s3_bucket_versioning is explicitly listed here — it controls data durability,
	// not access control, and the user confirmed it belongs in this category.
	nonSecurity := []string{
		"aws_s3_bucket_versioning",
		"aws_s3_bucket_logging",
		"aws_s3_bucket_lifecycle_configuration",
		"aws_s3_bucket_cors_configuration",
		"aws_s3_bucket_replication_configuration",
	}
	for _, rt := range nonSecurity {
		if parser.IsSecurityRelevantResourceType(rt) {
			t.Errorf("IsSecurityRelevantResourceType(%q) = true, want false (operational type, no auth impact)", rt)
		}
	}
}
