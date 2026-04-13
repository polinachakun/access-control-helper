package ir

import (
	"regexp"
	"strings"

	"access-control-helper/internal/resolver"
)

// Builder constructs an IR Config from resolved resources.
type Builder struct {
	resources map[string]*resolver.ResolvedResource
	graph     *resolver.DependencyGraph
	config    *Config
}

// NewBuilder creates a new Builder.
func NewBuilder(resources map[string]*resolver.ResolvedResource, graph *resolver.DependencyGraph) *Builder {
	return &Builder{
		resources: resources,
		graph:     graph,
		config:    &Config{},
	}
}

// Build constructs the IR Config from resolved resources.
func (b *Builder) Build() (*Config, error) {
	// First pass: build basic resources
	for ref, res := range b.resources {
		switch res.Type {
		case "aws_s3_bucket":
			b.buildS3Bucket(ref, res)
		case "aws_iam_role":
			b.buildIAMRole(ref, res)
		case "aws_iam_user":
			b.buildIAMUser(ref, res)
		case "aws_iam_policy":
			b.buildIAMPolicy(ref, res)
		case "aws_organizations_policy":
			b.buildOrgPolicy(ref, res)
		}
	}

	// Second pass: build policies that reference other resources
	for ref, res := range b.resources {
		switch res.Type {
		case "aws_s3_bucket_policy":
			b.buildBucketPolicy(ref, res)
		case "aws_iam_role_policy":
			b.buildRolePolicy(ref, res)
		case "aws_iam_user_policy":
			b.buildUserPolicy(ref, res)
		case "aws_s3_bucket_public_access_block":
			b.handlePublicAccessBlock(res)
		case "aws_iam_role_policy_attachment":
			b.handleRolePolicyAttachment(res)
		}
	}

	// Third pass: link attachments and update flags
	b.linkResources()

	return b.config, nil
}

// buildS3Bucket builds an S3Bucket from a resolved resource.
func (b *Builder) buildS3Bucket(ref string, res *resolver.ResolvedResource) {
	bucket := &S3Bucket{
		TFName: res.Name,
		Tags:   make(map[string]string),
	}

	// Extract tags
	if tags := b.getAttrAsMap(res, "tags"); tags != nil {
		bucket.Tags = tags
		if env, ok := tags["environment"]; ok {
			bucket.EnvTag = env
		} else if env, ok := tags["Environment"]; ok {
			bucket.EnvTag = env
		}
	}

	b.config.Buckets = append(b.config.Buckets, bucket)
}

// buildBucketPolicy builds a BucketPolicy from a resolved resource.
func (b *Builder) buildBucketPolicy(ref string, res *resolver.ResolvedResource) {
	policy := &BucketPolicy{
		TFName: res.Name,
	}

	// Extract bucket reference
	if bucket := b.getAttrAsString(res, "bucket"); bucket != "" {
		policy.BucketRef = extractResourceRef(bucket)
		if policy.BucketRef == "" {
			// It might be a direct reference in the resolved form
			for _, r := range res.References {
				if strings.HasPrefix(r, "aws_s3_bucket.") {
					policy.BucketRef = r
					break
				}
			}
		}
	}

	// Parse policy document
	if policyDoc := b.getAttrAsString(res, "policy"); policyDoc != "" {
		doc, err := ParsePolicyDocument(policyDoc)
		if err == nil && doc != nil {
			policy.Policy = doc
			b.analyzeBucketPolicy(policy, doc)
		}
	}

	b.config.BucketPolicies = append(b.config.BucketPolicies, policy)
}

// analyzeBucketPolicy extracts relevant information from a bucket policy.
func (b *Builder) analyzeBucketPolicy(policy *BucketPolicy, doc *IAMPolicyDocument) {
	for _, stmt := range doc.Statements {
		// Check for VPCE guard (explicit deny without correct VPCE)
		if stmt.IsDeny() && stmt.HasVPCECondition() {
			policy.DenyVpceID = stmt.GetVPCEID()
		}

		// Check for Allow with principals and actions
		if stmt.IsAllow() {
			for _, p := range stmt.GetPrincipalARNs() {
				policy.AllowPrincipals = append(policy.AllowPrincipals, p)
			}
			policy.AllowActions = append(policy.AllowActions, stmt.Actions...)

			// Check for ABAC condition
			if stmt.HasABACCondition() {
				policy.HasABAC = true
			}
		}

		// Check for general Deny (skip VPCE-conditional, already handled by DenyVpceID)
		if stmt.IsDeny() && !stmt.HasVPCECondition() {
			policy.DenyActions = append(policy.DenyActions, stmt.Actions...)
			for _, p := range stmt.GetPrincipalARNs() {
				policy.DenyPrincipals = append(policy.DenyPrincipals, p)
			}
		}
	}
}

// buildIAMRole builds an IAMRole from a resolved resource.
func (b *Builder) buildIAMRole(ref string, res *resolver.ResolvedResource) {
	role := &IAMRole{
		TFName: res.Name,
		Tags:   make(map[string]string),
	}

	// Extract name
	if name := b.getAttrAsString(res, "name"); name != "" {
		role.Name = name
	} else {
		role.Name = res.Name
	}

	// Extract tags
	if tags := b.getAttrAsMap(res, "tags"); tags != nil {
		role.Tags = tags
		if env, ok := tags["environment"]; ok {
			role.EnvTag = env
		} else if env, ok := tags["Environment"]; ok {
			role.EnvTag = env
		}
	}

	// Check for permissions boundary.
	// The HCL resolver evaluates `aws_iam_policy.name.arn` to a placeholder ARN string,
	// so extractResourceRef may return "" on the attribute value. We fall back to
	// res.References which always contains the raw resource ref.
	if boundary := b.getAttrAsString(res, "permissions_boundary"); boundary != "" {
		role.HasBoundary = true
		role.BoundaryRef = extractResourceRef(boundary)
	}
	if role.BoundaryRef == "" {
		for _, ref := range res.References {
			if strings.HasPrefix(ref, "aws_iam_policy.") {
				role.HasBoundary = true
				role.BoundaryRef = ref
				break
			}
		}
	}

	// Parse assume role policy
	if assumePolicy := b.getAttrAsString(res, "assume_role_policy"); assumePolicy != "" {
		doc, err := ParsePolicyDocument(assumePolicy)
		if err == nil {
			role.AssumeRolePolicy = doc
		}
	}

	b.config.Roles = append(b.config.Roles, role)
}

// buildRolePolicy builds a RolePolicy from a resolved resource.
func (b *Builder) buildRolePolicy(ref string, res *resolver.ResolvedResource) {
	rolePolicy := &RolePolicy{
		TFName: res.Name,
	}

	// Extract role reference
	if role := b.getAttrAsString(res, "role"); role != "" {
		rolePolicy.RoleRef = extractResourceRef(role)
		if rolePolicy.RoleRef == "" {
			for _, r := range res.References {
				if strings.HasPrefix(r, "aws_iam_role.") {
					rolePolicy.RoleRef = r
					break
				}
			}
		}
	}

	// Parse policy document
	if policyDoc := b.getAttrAsString(res, "policy"); policyDoc != "" {
		doc, err := ParsePolicyDocument(policyDoc)
		if err == nil {
			rolePolicy.Policy = doc
		}
	}

	b.config.RolePolicies = append(b.config.RolePolicies, rolePolicy)
}

// buildIAMUser builds an IAMUser from a resolved resource.
func (b *Builder) buildIAMUser(ref string, res *resolver.ResolvedResource) {
	user := &IAMUser{
		TFName: res.Name,
		Tags:   make(map[string]string),
	}

	// Extract name
	if name := b.getAttrAsString(res, "name"); name != "" {
		user.Name = name
	} else {
		user.Name = res.Name
	}

	// Extract tags
	if tags := b.getAttrAsMap(res, "tags"); tags != nil {
		user.Tags = tags
		if env, ok := tags["environment"]; ok {
			user.EnvTag = env
		} else if env, ok := tags["Environment"]; ok {
			user.EnvTag = env
		}
	}

	b.config.Users = append(b.config.Users, user)
}

// buildUserPolicy builds a UserPolicy from a resolved resource.
func (b *Builder) buildUserPolicy(ref string, res *resolver.ResolvedResource) {
	userPolicy := &UserPolicy{
		TFName: res.Name,
	}

	// Extract user reference
	if user := b.getAttrAsString(res, "user"); user != "" {
		userPolicy.UserRef = extractResourceRef(user)
		if userPolicy.UserRef == "" {
			for _, r := range res.References {
				if strings.HasPrefix(r, "aws_iam_user.") {
					userPolicy.UserRef = r
					break
				}
			}
		}
	}

	// Parse policy document
	if policyDoc := b.getAttrAsString(res, "policy"); policyDoc != "" {
		doc, err := ParsePolicyDocument(policyDoc)
		if err == nil {
			userPolicy.Policy = doc
		}
	}

	b.config.UserPolicies = append(b.config.UserPolicies, userPolicy)
}

// buildIAMPolicy builds an IAMPolicy from a resolved resource.
func (b *Builder) buildIAMPolicy(ref string, res *resolver.ResolvedResource) {
	policy := &IAMPolicy{
		TFName: res.Name,
	}

	// Extract name
	if name := b.getAttrAsString(res, "name"); name != "" {
		policy.Name = name
	} else {
		policy.Name = res.Name
	}

	// Parse policy document
	if policyDoc := b.getAttrAsString(res, "policy"); policyDoc != "" {
		doc, err := ParsePolicyDocument(policyDoc)
		if err == nil {
			policy.Policy = doc
		}
	}

	b.config.Policies = append(b.config.Policies, policy)
}

// buildOrgPolicy builds an OrgPolicy from a resolved resource.
func (b *Builder) buildOrgPolicy(ref string, res *resolver.ResolvedResource) {
	orgPolicy := &OrgPolicy{
		TFName: res.Name,
	}

	// Extract name
	if name := b.getAttrAsString(res, "name"); name != "" {
		orgPolicy.Name = name
	}

	// Extract type (defaults to SCP)
	if policyType := b.getAttrAsString(res, "type"); policyType != "" {
		orgPolicy.PolicyType = policyType
	} else {
		orgPolicy.PolicyType = "SERVICE_CONTROL_POLICY"
	}

	// Parse policy document (content attribute)
	if content := b.getAttrAsString(res, "content"); content != "" {
		doc, err := ParsePolicyDocument(content)
		if err == nil {
			orgPolicy.Policy = doc
			// Extract actions
			orgPolicy.AllowActions = doc.GetAllActions()
			orgPolicy.DenyActions = doc.GetDeniedActions()
		}
	}

	b.config.OrgPolicies = append(b.config.OrgPolicies, orgPolicy)
}

// handlePublicAccessBlock updates the corresponding bucket's HasBPA flag.
func (b *Builder) handlePublicAccessBlock(res *resolver.ResolvedResource) {
	// Find the bucket reference
	bucketRef := ""
	if bucket := b.getAttrAsString(res, "bucket"); bucket != "" {
		bucketRef = extractResourceRef(bucket)
	}
	if bucketRef == "" {
		for _, r := range res.References {
			if strings.HasPrefix(r, "aws_s3_bucket.") {
				bucketRef = r
				break
			}
		}
	}

	if bucketRef == "" {
		return
	}

	// Find and update the bucket
	bucketName := strings.TrimPrefix(bucketRef, "aws_s3_bucket.")
	for _, bucket := range b.config.Buckets {
		if bucket.TFName == bucketName {
			bucket.HasBPA = true
			break
		}
	}
}

// handleRolePolicyAttachment updates the corresponding role's HasRolePolicy flag.
func (b *Builder) handleRolePolicyAttachment(res *resolver.ResolvedResource) {
	// Find the role reference from attributes or references
	roleRef := ""
	if role := b.getAttrAsString(res, "role"); role != "" {
		roleRef = extractResourceRef(role)
	}
	if roleRef == "" {
		for _, r := range res.References {
			if strings.HasPrefix(r, "aws_iam_role.") {
				roleRef = r
				break
			}
		}
	}

	if roleRef == "" {
		return
	}

	// Find the policy reference from attributes or references
	policyRef := ""
	for _, r := range res.References {
		if strings.HasPrefix(r, "aws_iam_policy.") {
			policyRef = r
			break
		}
	}

	// Find and update the role
	roleName := strings.TrimPrefix(roleRef, "aws_iam_role.")
	for _, role := range b.config.Roles {
		if role.TFName == roleName {
			role.HasRolePolicy = true

			// Extract actions from the attached policy
			if policyRef != "" {
				policyName := strings.TrimPrefix(policyRef, "aws_iam_policy.")
				if p := b.config.GetPolicyByTFName(policyName); p != nil && p.Policy != nil {
					role.RolePolicyActions = append(role.RolePolicyActions, p.Policy.GetAllActions()...)
				}
			}
			break
		}
	}
}

// linkResources establishes relationships between resources.
func (b *Builder) linkResources() {
	// Link role policies to roles
	for _, rp := range b.config.RolePolicies {
		if rp.RoleRef == "" {
			continue
		}
		roleName := strings.TrimPrefix(rp.RoleRef, "aws_iam_role.")
		for _, role := range b.config.Roles {
			if role.TFName == roleName {
				role.HasRolePolicy = true
				if rp.Policy != nil {
					role.RolePolicyActions = append(role.RolePolicyActions, rp.Policy.GetAllActions()...)
				}
				break
			}
		}
	}

	// Link user policies to users
	for _, up := range b.config.UserPolicies {
		if up.UserRef == "" {
			continue
		}
		userName := strings.TrimPrefix(up.UserRef, "aws_iam_user.")
		for _, user := range b.config.Users {
			if user.TFName == userName {
				user.HasUserPolicy = true
				break
			}
		}
	}

	// Link boundaries to roles
	for _, role := range b.config.Roles {
		if role.BoundaryRef == "" {
			continue
		}
		policyName := strings.TrimPrefix(role.BoundaryRef, "aws_iam_policy.")
		if p := b.config.GetPolicyByTFName(policyName); p != nil && p.Policy != nil {
			role.BoundaryActions = p.Policy.GetAllActions()
		}
	}
}

// Helper methods

func (b *Builder) getAttrAsString(res *resolver.ResolvedResource, name string) string {
	if val, ok := res.Attributes[name]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func (b *Builder) getAttrAsMap(res *resolver.ResolvedResource, name string) map[string]string {
	if val, ok := res.Attributes[name]; ok {
		if m, ok := val.(map[string]interface{}); ok {
			result := make(map[string]string)
			for k, v := range m {
				if s, ok := v.(string); ok {
					result[k] = s
				}
			}
			return result
		}
	}
	return nil
}

// extractResourceRef extracts a resource reference from various formats.
func extractResourceRef(s string) string {
	// Try Terraform reference format: aws_s3_bucket.name.attribute
	re := regexp.MustCompile(`(aws_[a-z0-9_]+)\.([a-z0-9_]+)`)
	matches := re.FindStringSubmatch(s)
	if len(matches) >= 3 {
		return matches[1] + "." + matches[2]
	}
	return ""
}

// BuildFromResources is a convenience function that creates a Builder and builds the Config.
func BuildFromResources(resources map[string]*resolver.ResolvedResource, graph *resolver.DependencyGraph) (*Config, error) {
	builder := NewBuilder(resources, graph)
	return builder.Build()
}
