package parser

import "github.com/hashicorp/hcl/v2"

// HCL schemas for AWS Terraform resource types.
// These define which attributes and blocks are expected to find in each resource type.

// ResourceSchema returns the HCL schema for a given resource type.
func ResourceSchema(resourceType string) *hcl.BodySchema {
	switch resourceType {
	case "aws_s3_bucket":
		return s3BucketSchema
	case "aws_s3_bucket_policy":
		return s3BucketPolicySchema
	case "aws_s3_bucket_public_access_block":
		return s3BucketPublicAccessBlockSchema
	case "aws_iam_role":
		return iamRoleSchema
	case "aws_iam_role_policy":
		return iamRolePolicySchema
	case "aws_iam_role_policy_attachment":
		return iamRolePolicyAttachmentSchema
	case "aws_iam_user":
		return iamUserSchema
	case "aws_iam_user_policy":
		return iamUserPolicySchema
	case "aws_iam_policy":
		return iamPolicySchema
	case "aws_organizations_policy":
		return orgPolicySchema
	default:
		return genericResourceSchema
	}
}

// genericResourceSchema is used for unknown resource types.
var genericResourceSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{},
	Blocks:     []hcl.BlockHeaderSchema{},
}

// s3BucketSchema defines the schema for aws_s3_bucket resources.
var s3BucketSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "bucket", Required: false},
		{Name: "bucket_prefix", Required: false},
		{Name: "acl", Required: false},
		{Name: "tags", Required: false},
		{Name: "force_destroy", Required: false},
	},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "versioning"},
		{Type: "logging"},
		{Type: "lifecycle_rule"},
		{Type: "server_side_encryption_configuration"},
		{Type: "website"},
		{Type: "cors_rule"},
		{Type: "grant"},
		{Type: "object_lock_configuration"},
		{Type: "replication_configuration"},
	},
}

// s3BucketPolicySchema defines the schema for aws_s3_bucket_policy resources.
var s3BucketPolicySchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "bucket", Required: true},
		{Name: "policy", Required: true},
	},
	Blocks: []hcl.BlockHeaderSchema{},
}

// s3BucketPublicAccessBlockSchema defines the schema for aws_s3_bucket_public_access_block.
var s3BucketPublicAccessBlockSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "bucket", Required: true},
		{Name: "block_public_acls", Required: false},
		{Name: "block_public_policy", Required: false},
		{Name: "ignore_public_acls", Required: false},
		{Name: "restrict_public_buckets", Required: false},
	},
	Blocks: []hcl.BlockHeaderSchema{},
}

// iamRoleSchema defines the schema for aws_iam_role resources.
var iamRoleSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "name", Required: false},
		{Name: "name_prefix", Required: false},
		{Name: "assume_role_policy", Required: true},
		{Name: "path", Required: false},
		{Name: "description", Required: false},
		{Name: "max_session_duration", Required: false},
		{Name: "permissions_boundary", Required: false},
		{Name: "force_detach_policies", Required: false},
		{Name: "tags", Required: false},
		{Name: "managed_policy_arns", Required: false},
	},
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "inline_policy"},
	},
}

// iamRolePolicySchema defines the schema for aws_iam_role_policy resources.
var iamRolePolicySchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "name", Required: false},
		{Name: "name_prefix", Required: false},
		{Name: "role", Required: true},
		{Name: "policy", Required: true},
	},
	Blocks: []hcl.BlockHeaderSchema{},
}

// iamRolePolicyAttachmentSchema defines the schema for aws_iam_role_policy_attachment.
var iamRolePolicyAttachmentSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "role", Required: true},
		{Name: "policy_arn", Required: true},
	},
	Blocks: []hcl.BlockHeaderSchema{},
}

// iamUserSchema defines the schema for aws_iam_user resources.
var iamUserSchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "name", Required: true},
		{Name: "path", Required: false},
		{Name: "permissions_boundary", Required: false},
		{Name: "force_destroy", Required: false},
		{Name: "tags", Required: false},
	},
	Blocks: []hcl.BlockHeaderSchema{},
}

// iamUserPolicySchema defines the schema for aws_iam_user_policy resources.
var iamUserPolicySchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "name", Required: false},
		{Name: "name_prefix", Required: false},
		{Name: "user", Required: true},
		{Name: "policy", Required: true},
	},
	Blocks: []hcl.BlockHeaderSchema{},
}

// iamPolicySchema defines the schema for aws_iam_policy resources.
var iamPolicySchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "name", Required: false},
		{Name: "name_prefix", Required: false},
		{Name: "path", Required: false},
		{Name: "description", Required: false},
		{Name: "policy", Required: true},
		{Name: "tags", Required: false},
	},
	Blocks: []hcl.BlockHeaderSchema{},
}

// orgPolicySchema defines the schema for aws_organizations_policy resources.
var orgPolicySchema = &hcl.BodySchema{
	Attributes: []hcl.AttributeSchema{
		{Name: "name", Required: true},
		{Name: "content", Required: true},
		{Name: "description", Required: false},
		{Name: "type", Required: false},
		{Name: "tags", Required: false},
	},
	Blocks: []hcl.BlockHeaderSchema{},
}

// TopLevelSchema is the schema for the top-level Terraform configuration.
var TopLevelSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{Type: "resource", LabelNames: []string{"type", "name"}},
		{Type: "data", LabelNames: []string{"type", "name"}},
		{Type: "locals"},
		{Type: "variable", LabelNames: []string{"name"}},
		{Type: "output", LabelNames: []string{"name"}},
		{Type: "provider", LabelNames: []string{"name"}},
		{Type: "terraform"},
		{Type: "module", LabelNames: []string{"name"}},
	},
}

// SupportedResourceTypes lists all resource types we handle.
var SupportedResourceTypes = map[string]bool{
	"aws_s3_bucket":                     true,
	"aws_s3_bucket_policy":              true,
	"aws_s3_bucket_public_access_block": true,
	"aws_iam_role":                      true,
	"aws_iam_role_policy":               true,
	"aws_iam_role_policy_attachment":    true,
	"aws_iam_user":                      true,
	"aws_iam_user_policy":               true,
	"aws_iam_policy":                    true,
	"aws_organizations_policy":          true,
}

// IsSupportedResourceType returns true if the resource type is supported.
func IsSupportedResourceType(resourceType string) bool {
	return SupportedResourceTypes[resourceType]
}
