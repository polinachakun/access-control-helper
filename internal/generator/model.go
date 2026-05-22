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
		// Object — read
		"s3:GetObject",
		"s3:GetObjectAcl",
		"s3:GetObjectAttributes",
		"s3:GetObjectLegalHold",
		"s3:GetObjectRetention",
		"s3:GetObjectTagging",
		"s3:GetObjectTorrent",
		"s3:GetObjectVersion",
		"s3:GetObjectVersionAcl",
		"s3:GetObjectVersionAttributes",
		"s3:GetObjectVersionForReplication",
		"s3:GetObjectVersionTagging",
		"s3:GetObjectVersionTorrent",
		"s3:ListMultipartUploadParts",
		"s3:AbortMultipartUpload",
		"s3:DeleteObject",
		"s3:DeleteObjectTagging",
		"s3:DeleteObjectVersion",
		"s3:DeleteObjectVersionTagging",
		"s3:PutObject",
		"s3:PutObjectAcl",
		"s3:PutObjectLegalHold",
		"s3:PutObjectRetention",
		"s3:PutObjectTagging",
		"s3:ReplicateDelete",
		"s3:ReplicateObject",
		"s3:ReplicateTags",
		"s3:RestoreObject",
		"s3:GetAccelerateConfiguration",
		"s3:GetAnalyticsConfiguration",
		"s3:GetBucketAcl",
		"s3:GetBucketCORS",
		"s3:GetBucketLocation",
		"s3:GetBucketLogging",
		"s3:GetBucketNotification",
		"s3:GetBucketObjectLockConfiguration",
		"s3:GetBucketOwnershipControls",
		"s3:GetBucketPolicy",
		"s3:GetBucketPolicyStatus",
		"s3:GetBucketPublicAccessBlock",
		"s3:GetBucketRequestPayment",
		"s3:GetBucketTagging",
		"s3:GetBucketVersioning",
		"s3:GetBucketWebsite",
		"s3:GetEncryptionConfiguration",
		"s3:GetIntelligentTieringConfiguration",
		"s3:GetInventoryConfiguration",
		"s3:GetLifecycleConfiguration",
		"s3:GetMetricsConfiguration",
		"s3:GetReplicationConfiguration",
		"s3:ListBucket",
		"s3:ListBucketMultipartUploads",
		"s3:ListBucketVersions",
		"s3:CreateBucket",
		"s3:DeleteBucket",
		"s3:DeleteBucketOwnershipControls",
		"s3:DeleteBucketPolicy",
		"s3:DeleteBucketWebsite",
		"s3:PutAccelerateConfiguration",
		"s3:PutAnalyticsConfiguration",
		"s3:PutBucketAcl",
		"s3:PutBucketCORS",
		"s3:PutBucketLogging",
		"s3:PutBucketNotification",
		"s3:PutBucketObjectLockConfiguration",
		"s3:PutBucketOwnershipControls",
		"s3:PutBucketPolicy",
		"s3:PutBucketPublicAccessBlock",
		"s3:PutBucketRequestPayment",
		"s3:PutBucketTagging",
		"s3:PutBucketVersioning",
		"s3:PutBucketWebsite",
		"s3:PutEncryptionConfiguration",
		"s3:PutIntelligentTieringConfiguration",
		"s3:PutInventoryConfiguration",
		"s3:PutLifecycleConfiguration",
		"s3:PutMetricsConfiguration",
		"s3:PutReplicationConfiguration",
		"s3:GetAccessPoint",
		"s3:GetAccessPointConfigurationForObjectLambda",
		"s3:GetAccessPointForObjectLambda",
		"s3:GetAccessPointPolicy",
		"s3:GetAccessPointPolicyForObjectLambda",
		"s3:GetAccessPointPolicyStatus",
		"s3:GetAccessPointPolicyStatusForObjectLambda",
		"s3:GetAccountPublicAccessBlock",
		"s3:GetJobTagging",
		"s3:GetMultiRegionAccessPoint",
		"s3:GetMultiRegionAccessPointPolicy",
		"s3:GetMultiRegionAccessPointPolicyStatus",
		"s3:GetMultiRegionAccessPointRoutes",
		"s3:GetStorageLensConfiguration",
		"s3:GetStorageLensConfigurationTagging",
		"s3:GetStorageLensDashboard",
		"s3:GetStorageLensGroup",
		"s3:ListAccessPoints",
		"s3:ListAccessPointsForObjectLambda",
		"s3:ListAllMyBuckets",
		"s3:ListJobs",
		"s3:ListMultiRegionAccessPoints",
		"s3:ListStorageLensConfigurations",
		"s3:ListStorageLensGroups",
		"s3:ListTagsForResource",
		"s3:DescribeJob",
		"s3:DescribeMultiRegionAccessPointOperation",
		"s3:CreateAccessPoint",
		"s3:CreateAccessPointForObjectLambda",
		"s3:CreateJob",
		"s3:CreateMultiRegionAccessPoint",
		"s3:CreateStorageLensGroup",
		"s3:DeleteAccessPoint",
		"s3:DeleteAccessPointForObjectLambda",
		"s3:DeleteAccessPointPolicy",
		"s3:DeleteAccessPointPolicyForObjectLambda",
		"s3:DeleteJobTagging",
		"s3:DeleteMultiRegionAccessPoint",
		"s3:DeleteStorageLensConfiguration",
		"s3:DeleteStorageLensConfigurationTagging",
		"s3:DeleteStorageLensGroup",
		"s3:PutAccessPointConfigurationForObjectLambda",
		"s3:PutAccessPointPolicy",
		"s3:PutAccessPointPolicyForObjectLambda",
		"s3:PutAccountPublicAccessBlock",
		"s3:PutJobTagging",
		"s3:PutMultiRegionAccessPointPolicy",
		"s3:PutStorageLensConfiguration",
		"s3:PutStorageLensConfigurationTagging",
		"s3:SubmitMultiRegionAccessPointRoutes",
		"s3:TagResource",
		"s3:UntagResource",
		"s3:UpdateJobPriority",
		"s3:UpdateJobStatus",
		"s3:UpdateStorageLensGroup",
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

		if len(parts) == 2 {
			if _, ok := SupportedActionsByService[strings.ToLower(parts[0])]; !ok {
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
