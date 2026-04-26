// Package ir defines the intermediate representation (IR) for AWS resources.
// This domain model is independent of Terraform and HCL parsing details.
package ir

import "fmt"

// Config holds the complete parsed AWS configuration.
type Config struct {
	Buckets        []*S3Bucket
	BucketPolicies []*BucketPolicy
	Roles          []*IAMRole
	RolePolicies   []*RolePolicy
	Users          []*IAMUser
	UserPolicies   []*UserPolicy
	Policies       []*IAMPolicy
	OrgPolicies    []*OrgPolicy
}

// S3Bucket represents an aws_s3_bucket resource.
type S3Bucket struct {
	TFName string            // Terraform resource name
	Tags   map[string]string // Resource tags
	EnvTag string            // Environment tag value (extracted from tags)
	HasBPA bool              // Has aws_s3_bucket_public_access_block
}

// BucketPolicy represents an aws_s3_bucket_policy resource.
type BucketPolicy struct {
	TFName     string
	BucketRef  string
	Policy     *IAMPolicyDocument
	DenyVpceID string

	AllowPrincipals     []string
	AllowAnyPrincipal   bool
	AllowActions        []string
	AllowNotActions     []string
	HasAllowNotAction   bool
	AllowBucketResource bool
	AllowObjectResource bool

	DenyActions        []string
	DenyNotActions     []string
	HasDenyNotAction   bool
	DenyPrincipals     []string
	DenyAnyPrincipal   bool
	DenyBucketResource bool
	DenyObjectResource bool

	HasABAC bool
}

// IAMRole represents an aws_iam_role resource.
type IAMRole struct {
	TFName            string // Terraform resource name
	Name              string // AWS role name
	EnvTag            string // Environment tag value
	Tags              map[string]string
	HasRolePolicy     bool     // Has attached role policy
	RolePolicyActions []string // Actions explicitly allowed by role policies
	RoleDenyActions   []string // Actions explicitly denied by role policies (Bug 2 fix)
	RoleNotActions    []string // Actions excluded from Allow via NotAction (Bug 4 fix)
	HasRoleNotAction  bool     // Role policy uses NotAction in an Allow statement (Bug 4 fix)
	HasBoundary       bool     // Has permissions boundary
	BoundaryRef       string   // Reference to boundary policy
	BoundaryActions   []string // Actions allowed by boundary
	HasSessionPolicy  bool     // AssumeRole with session policy
	AssumeRolePolicy  *IAMPolicyDocument
	CrossAccount      bool // Principal is from a different AWS account (Bug 3 fix)
}

// RolePolicy represents an aws_iam_role_policy resource.
type RolePolicy struct {
	TFName  string             // Terraform resource name
	RoleRef string             // Reference to the role
	Policy  *IAMPolicyDocument // Parsed policy document
}

// IAMUser represents an aws_iam_user resource.
type IAMUser struct {
	TFName        string
	Name          string
	EnvTag        string
	Tags          map[string]string
	HasUserPolicy bool
}

// UserPolicy represents an aws_iam_user_policy resource.
type UserPolicy struct {
	TFName  string
	UserRef string
	Policy  *IAMPolicyDocument
}

// IAMPolicy represents an aws_iam_policy resource (standalone policy).
type IAMPolicy struct {
	TFName string
	Name   string
	ARN    string
	Policy *IAMPolicyDocument
}

// OrgPolicy represents an aws_organizations_policy resource.
type OrgPolicy struct {
	TFName       string             // Terraform resource name
	Name         string             // Policy name
	PolicyType   string             // "SERVICE_CONTROL_POLICY" (SCP) or "RESOURCE_CONTROL_POLICY" (RCP)
	Policy       *IAMPolicyDocument // Parsed policy document
	AllowActions []string           // Actions explicitly allowed
	DenyActions  []string           // Actions explicitly denied
}

// IAMPolicyDocument represents a parsed IAM policy document.
type IAMPolicyDocument struct {
	Version    string       `json:"Version"`
	ID         string       `json:"Id,omitempty"`
	Statements []*Statement `json:"Statement"`
}

// Statement represents a single statement in an IAM policy.
type Statement struct {
	SID        string      `json:"Sid,omitempty"`
	Effect     string      `json:"Effect"`
	Actions    []string    // Normalized from Action/NotAction
	NotActions []string    // NotAction field
	Resources  []string    // Normalized from Resource/NotResource
	Principals []Principal // Normalized from Principal
	Conditions []Condition // Parsed conditions
}

// Principal represents a principal in an IAM policy statement.
type Principal struct {
	Type  string // "AWS", "Service", "Federated", "*"
	Value string // ARN, service name, or "*"
}

// Condition represents a condition in an IAM policy statement.
type Condition struct {
	Operator string // "StringEquals", "StringNotEquals", "ArnEquals", etc.
	Key      string // "aws:sourceVpce", "aws:PrincipalTag/environment", etc.
	Values   []string
}

// IsSCP returns true if this is a Service Control Policy.
func (op *OrgPolicy) IsSCP() bool {
	return op.PolicyType == "SERVICE_CONTROL_POLICY" || op.PolicyType == "SCP"
}

// IsRCP returns true if this is a Resource Control Policy.
func (op *OrgPolicy) IsRCP() bool {
	return op.PolicyType == "RESOURCE_CONTROL_POLICY" || op.PolicyType == "RCP"
}

// GetBucketByTFName finds a bucket by its Terraform name.
func (c *Config) GetBucketByTFName(name string) *S3Bucket {
	for _, b := range c.Buckets {
		if b.TFName == name {
			return b
		}
	}
	return nil
}

// GetRoleByTFName finds a role by its Terraform name.
func (c *Config) GetRoleByTFName(name string) *IAMRole {
	for _, r := range c.Roles {
		if r.TFName == name {
			return r
		}
	}
	return nil
}

// GetUserByTFName finds a user by its Terraform name.
func (c *Config) GetUserByTFName(name string) *IAMUser {
	for _, u := range c.Users {
		if u.TFName == name {
			return u
		}
	}
	return nil
}

// GetPolicyByTFName finds a standalone IAM policy by its Terraform name.
func (c *Config) GetPolicyByTFName(name string) *IAMPolicy {
	for _, p := range c.Policies {
		if p.TFName == name {
			return p
		}
	}
	return nil
}

// SCPs returns all Service Control Policies.
func (c *Config) SCPs() []*OrgPolicy {
	var scps []*OrgPolicy
	for _, op := range c.OrgPolicies {
		if op.IsSCP() {
			scps = append(scps, op)
		}
	}
	return scps
}

// RCPs returns all Resource Control Policies.
func (c *Config) RCPs() []*OrgPolicy {
	var rcps []*OrgPolicy
	for _, op := range c.OrgPolicies {
		if op.IsRCP() {
			rcps = append(rcps, op)
		}
	}
	return rcps
}

type ValidationError struct {
	Fatal   bool
	Message string
}

// Validate checks invariants on the built Config
func (c *Config) Validate() []ValidationError {
	var errs []ValidationError

	if len(c.Buckets) == 0 {
		errs = append(errs, ValidationError{Fatal: true,
			Message: "no S3 buckets found in configuration; nothing to analyse"})
	}
	if len(c.Roles) == 0 {
		errs = append(errs, ValidationError{Fatal: true,
			Message: "no IAM roles found in configuration; nothing to analyse"})
	}

	for _, bp := range c.BucketPolicies {
		if bp.BucketRef == "" {
			errs = append(errs, ValidationError{
				Message: fmt.Sprintf("bucket policy %q has no resolvable bucket reference and will appear unattached", bp.TFName)})
		}
		hasActions := len(bp.AllowActions)+len(bp.DenyActions)+
			len(bp.AllowNotActions)+len(bp.DenyNotActions) > 0
		if !hasActions && !bp.AllowAnyPrincipal && !bp.DenyAnyPrincipal && bp.DenyVpceID == "" {
			errs = append(errs, ValidationError{
				Message: fmt.Sprintf("bucket policy %q has no actions and no VPCE condition; it will have no effect", bp.TFName)})
		}
	}

	return errs
}
