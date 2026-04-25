package ir

import (
	"fmt"
	"regexp"
	"strings"

	"access-control-helper/internal/resolver"
)

// Builder constructs an IR Config from resolved resources.
type Builder struct {
	resources map[string]*resolver.ResolvedResource
	graph     *resolver.DependencyGraph
	config    *Config
	warnings  []string
}

func (b *Builder) Warnings() []string { return b.warnings }

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
	bucketRef := ""

	if bucket := b.getAttrAsString(res, "bucket"); bucket != "" {
		bucketRef = extractResourceRef(bucket)
		if bucketRef == "" {
			for _, r := range res.References {
				if strings.HasPrefix(r, "aws_s3_bucket.") {
					bucketRef = r
					break
				}
			}
		}
	}

	policyDoc := b.getAttrAsString(res, "policy")
	if policyDoc == "" {
		return
	}

	doc, err := ParsePolicyDocument(policyDoc)
	if err != nil || doc == nil {
		b.warnings = append(b.warnings, fmt.Sprintf(
			"bucket policy %q: failed to parse policy document: %v", res.Name, err))
		return
	}

	stmtIdx := 0
	for _, stmt := range doc.Statements {
		stmtIdx++
		entries := b.expandBucketPolicyStatement(res.Name, bucketRef, stmtIdx, stmt)
		b.config.BucketPolicies = append(b.config.BucketPolicies, entries...)
	}
}

func (b *Builder) expandBucketPolicyStatement(baseName, bucketRef string, stmtIdx int, stmt *Statement) []*BucketPolicy {
	if stmt == nil {
		return nil
	}

	principals := stmt.GetPrincipalARNs()
	anyPrincipal := stmt.HasWildcardPrincipal()

	if anyPrincipal {
		principals = append([]string{"*"}, principals...)
	}
	if len(principals) == 0 {
		b.warnings = append(b.warnings, fmt.Sprintf(
			"bucket policy %s statement %d has no principals; statement skipped", baseName, stmtIdx))
		return nil
	}

	var out []*BucketPolicy
	for i, principal := range principals {
		p := &BucketPolicy{
			TFName:              fmt.Sprintf("%s_stmt_%d_pr_%d", baseName, stmtIdx, i+1),
			BucketRef:           bucketRef,
			AllowBucketResource: stmt.HasBucketLevelResource(),
			AllowObjectResource: stmt.HasObjectLevelResource(),
			DenyBucketResource:  stmt.HasBucketLevelResource(),
			DenyObjectResource:  stmt.HasObjectLevelResource(),
		}

		if stmt.HasABACCondition() {
			p.HasABAC = true
		}

		if stmt.IsAllow() {
			if len(stmt.NotActions) > 0 {
				p.HasAllowNotAction = true
				p.AllowNotActions = append(p.AllowNotActions, stmt.NotActions...)
			} else {
				p.AllowActions = append(p.AllowActions, stmt.Actions...)
			}
			switch principal {
			case "*":
				p.AllowAnyPrincipal = true
			case "":
			default:
				p.AllowPrincipals = []string{principal}
			}
		}

		if stmt.IsDeny() && stmt.HasVPCECondition() {
			p.DenyVpceID = stmt.GetVPCEID()
		}

		if stmt.IsDeny() && !stmt.HasVPCECondition() {
			// Bug 4 fix: a statement uses either Action or NotAction, never both.
			if len(stmt.NotActions) > 0 {
				p.HasDenyNotAction = true
				p.DenyNotActions = append(p.DenyNotActions, stmt.NotActions...)
			} else {
				p.DenyActions = append(p.DenyActions, stmt.Actions...)
			}
			switch principal {
			case "*":
				p.DenyAnyPrincipal = true
			case "":
			default:
				p.DenyPrincipals = []string{principal}
			}
		}

		out = append(out, p)
	}

	return out
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
		if err != nil {
			b.warnings = append(b.warnings, fmt.Sprintf(
				"role policy %q: failed to parse policy document: %v", res.Name, err))
		} else {
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
		if err != nil {
			b.warnings = append(b.warnings, fmt.Sprintf(
				"IAM policy %q: failed to parse policy document: %v", res.Name, err))
		} else {
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
		if err != nil {
			b.warnings = append(b.warnings, fmt.Sprintf(
				"org policy %q: failed to parse policy document: %v", res.Name, err))
		} else {
			orgPolicy.Policy = doc
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
					// Bug 2 fix: collect explicit deny actions from attached policies
					role.RoleDenyActions = append(role.RoleDenyActions, p.Policy.GetDeniedActions()...)
					// Bug 4 fix: collect NotAction exclusions from Allow statements
					for _, stmt := range p.Policy.Statements {
						if stmt.IsAllow() && len(stmt.NotActions) > 0 {
							role.HasRoleNotAction = true
							role.RoleNotActions = append(role.RoleNotActions, stmt.NotActions...)
						}
					}
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
					// Bug 2 fix: collect explicit deny actions from inline role policies
					role.RoleDenyActions = append(role.RoleDenyActions, rp.Policy.GetDeniedActions()...)
					// Bug 4 fix: collect NotAction exclusions from Allow statements
					for _, stmt := range rp.Policy.Statements {
						if stmt.IsAllow() && len(stmt.NotActions) > 0 {
							role.HasRoleNotAction = true
							role.RoleNotActions = append(role.RoleNotActions, stmt.NotActions...)
						}
					}
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

func BuildFromResources(resources map[string]*resolver.ResolvedResource, graph *resolver.DependencyGraph) (*Config, []string, error) {
	b := NewBuilder(resources, graph)
	config, err := b.Build()
	return config, b.Warnings(), err
}
