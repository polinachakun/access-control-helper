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

func (b *Builder) buildS3Bucket(ref string, res *resolver.ResolvedResource) {
	bucket := &S3Bucket{
		TFName: res.Name,
		Tags:   make(map[string]string),
	}

	if name := b.getAttrAsString(res, "bucket"); name != "" {
		bucket.BucketName = name
	}

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
// Emits a warning when the policy document cannot be parsed (e.g. because it
// contains unresolved Terraform variable references) and skips the policy so
// that the rest of the analysis can continue. The caller should treat results
// as a lower bound when any policy is skipped.
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
		if looksLikeUnresolvedRef(policyDoc) {
			// Terraform variable/reference in the policy — valid Terraform but
			// not statically evaluable. Skip this policy and continue analysis.
			b.warnings = append(b.warnings, fmt.Sprintf(
				"bucket policy %q: skipped — policy document contains unresolved "+
					"Terraform references (analysis is a lower bound)", res.Name))
			return
		}
		// Statically invalid JSON — AWS would reject this at deploy time.
		b.warnings = append(b.warnings, fmt.Sprintf(
			"bucket policy %q: skipped — policy document is not valid JSON: %v", res.Name, err))
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

	sid := stmt.SID
	if sid == "" {
		sid = fmt.Sprintf("%d", stmtIdx)
	}

	if stmt.HasNotResource {
		b.warnings = append(b.warnings, fmt.Sprintf(
			"bucket policy %s statement %s: NotResource [%s] is not supported by this verifier; statement skipped",
			baseName, sid, strings.Join(stmt.NotResources, ", ")))
		return nil
	}

	if stmt.HasNotPrincipal {
		notPrincipals := make([]string, 0, len(stmt.NotPrincipals))
		for _, p := range stmt.NotPrincipals {
			notPrincipals = append(notPrincipals, p.Value)
		}
		b.warnings = append(b.warnings, fmt.Sprintf(
			"bucket policy %s statement %s: NotPrincipal [%s] is not supported by this verifier; statement skipped",
			baseName, sid, strings.Join(notPrincipals, ", ")))
		return nil
	}

	if len(stmt.UnrecognizedConditions) > 0 {
		keys := make([]string, 0, len(stmt.UnrecognizedConditions))
		for _, c := range stmt.UnrecognizedConditions {
			keys = append(keys, fmt.Sprintf("%s/%s", c.Operator, c.Key))
		}
		effect := strings.ToLower(stmt.Effect)
		approximation := "statement modeled as unconditional allow (may over-grant access in analysis)"
		if strings.EqualFold(stmt.Effect, "Deny") {
			// Conditional denies are skipped entirely rather than approximated as
			// unconditional: skipping may under-restrict, but unconditional deny
			// would block all access even for requests that satisfy the condition.
			approximation = "conditional deny not modeled (may under-restrict; runtime condition unknown)"
		}
		b.warnings = append(b.warnings, fmt.Sprintf(
			"bucket policy %s statement %s: unrecognized %s conditions [%s] are ignored; %s",
			baseName, sid, effect, strings.Join(keys, ", "), approximation))
	}

	principals := stmt.GetPrincipalARNs()
	anyPrincipal := stmt.HasWildcardPrincipal()

	if anyPrincipal {
		principals = append([]string{"*"}, principals...)
	}
	for _, svc := range stmt.GetServicePrincipals() {
		principals = append(principals, svc)
		b.registerServicePrincipal(svc)
	}
	if len(principals) == 0 {
		b.warnings = append(b.warnings, fmt.Sprintf(
			"bucket policy %s statement %d has no principals; statement skipped", baseName, stmtIdx))
		return nil
	}

	var out []*BucketPolicy
	for i, principal := range principals {
		p := &BucketPolicy{
			TFName:               fmt.Sprintf("%s_stmt_%d_pr_%d", baseName, stmtIdx, i+1),
			OriginalPolicyTFName: baseName,
			BucketRef:            bucketRef,
			AllowBucketResource:  stmt.HasBucketLevelResource(),
			AllowObjectResource:  stmt.HasObjectLevelResource(),
			DenyBucketResource:   stmt.HasBucketLevelResource(),
			DenyObjectResource:   stmt.HasObjectLevelResource(),
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
			// Store unrecognized conditions so the reporter can mark grants as
			// CONDITIONAL_ALLOW instead of ALLOW.
			if len(stmt.UnrecognizedConditions) > 0 {
				p.AllowUnrecognizedConditions = stmt.UnrecognizedConditions
			}
		}

		if stmt.IsDeny() && stmt.HasVPCECondition() {
			p.DenyVpceID = stmt.GetVPCEID()
		}

		// Deny with only unrecognized conditions: skip the deny rather than
		// approximating as unconditional deny. The warning above already notifies
		// the user. This avoids blocking all access for what is effectively a
		// conditional deny (e.g. aws:SecureTransport = false).
		if stmt.IsDeny() && !stmt.HasVPCECondition() && len(stmt.UnrecognizedConditions) == 0 {
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

func (b *Builder) analyzeBucketPolicy(policy *BucketPolicy, doc *IAMPolicyDocument) {
	for _, stmt := range doc.Statements {
		if stmt.IsDeny() && stmt.HasVPCECondition() {
			policy.DenyVpceID = stmt.GetVPCEID()
		}

		if stmt.IsAllow() {
			for _, p := range stmt.GetPrincipalARNs() {
				policy.AllowPrincipals = append(policy.AllowPrincipals, p)
			}
			policy.AllowActions = append(policy.AllowActions, stmt.Actions...)

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

func (b *Builder) buildIAMRole(ref string, res *resolver.ResolvedResource) {
	role := &IAMRole{
		TFName:                        res.Name,
		Tags:                          make(map[string]string),
		IdentityAllowActionsPerBucket: make(map[string][]string),
		BoundaryActionsPerBucket:      make(map[string][]string),
	}

	if name := b.getAttrAsString(res, "name"); name != "" {
		role.Name = name
	} else {
		role.Name = res.Name
	}

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
	// res.References which always contains the raw resource ref  but only when
	// permissions_boundary is actually set, to avoid picking up aws_iam_policy.*
	// references from unrelated attributes like managed_policy_arns.
	if boundary := b.getAttrAsString(res, "permissions_boundary"); boundary != "" {
		role.HasBoundary = true
		role.BoundaryRef = extractResourceRef(boundary)
		if role.BoundaryRef == "" {
			for _, ref := range res.References {
				if strings.HasPrefix(ref, "aws_iam_policy.") {
					role.BoundaryRef = ref
					break
				}
			}
		}
	}

	if assumePolicy := b.getAttrAsString(res, "assume_role_policy"); assumePolicy != "" {
		doc, err := ParsePolicyDocument(assumePolicy)
		if err == nil {
			role.AssumeRolePolicy = doc
		}
	}

	for _, nav := range NavResource(res).Blocks("inline_policy") {
		doc, err := ParsePolicyDocument(nav.Str("policy"))
		if err != nil {
			b.warnings = append(b.warnings, fmt.Sprintf(
				"role %q inline_policy: failed to parse policy document: %v", res.Name, err))
			continue
		}
		role.HasRolePolicy = true
		role.RolePolicyActions = append(role.RolePolicyActions, doc.GetAllActions()...)
		role.RoleDenyActions = append(role.RoleDenyActions, doc.GetDeniedActions()...)
		mergePerBucketActions(role.IdentityAllowActionsPerBucket, doc.GetAllowActionsPerBucket())
		for _, stmt := range doc.Statements {
			if stmt.IsAllow() && len(stmt.NotActions) > 0 {
				role.HasRoleNotAction = true
				role.RoleNotActions = append(role.RoleNotActions, stmt.NotActions...)
			}
		}
	}

	b.config.Roles = append(b.config.Roles, role)
}

func (b *Builder) buildRolePolicy(ref string, res *resolver.ResolvedResource) {
	rolePolicy := &RolePolicy{
		TFName: res.Name,
	}

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

func (b *Builder) buildIAMUser(ref string, res *resolver.ResolvedResource) {
	user := &IAMUser{
		TFName:                        res.Name,
		Tags:                          make(map[string]string),
		IdentityAllowActionsPerBucket: make(map[string][]string),
		BoundaryActionsPerBucket:      make(map[string][]string),
	}

	if name := b.getAttrAsString(res, "name"); name != "" {
		user.Name = name
	} else {
		user.Name = res.Name
	}

	if tags := b.getAttrAsMap(res, "tags"); tags != nil {
		user.Tags = tags
		if env, ok := tags["environment"]; ok {
			user.EnvTag = env
		} else if env, ok := tags["Environment"]; ok {
			user.EnvTag = env
		}
	}

	// Check for permissions boundary (parallel to buildIAMRole).
	if boundary := b.getAttrAsString(res, "permissions_boundary"); boundary != "" {
		user.HasBoundary = true
		user.BoundaryRef = extractResourceRef(boundary)
		if user.BoundaryRef == "" {
			for _, r := range res.References {
				if strings.HasPrefix(r, "aws_iam_policy.") {
					user.BoundaryRef = r
					break
				}
			}
		}
	}

	b.config.Users = append(b.config.Users, user)
}

func (b *Builder) buildUserPolicy(ref string, res *resolver.ResolvedResource) {
	userPolicy := &UserPolicy{
		TFName: res.Name,
	}

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

	if policyDoc := b.getAttrAsString(res, "policy"); policyDoc != "" {
		doc, err := ParsePolicyDocument(policyDoc)
		if err == nil {
			userPolicy.Policy = doc
		}
	}

	b.config.UserPolicies = append(b.config.UserPolicies, userPolicy)
}

func (b *Builder) buildIAMPolicy(ref string, res *resolver.ResolvedResource) {
	policy := &IAMPolicy{
		TFName: res.Name,
	}

	if name := b.getAttrAsString(res, "name"); name != "" {
		policy.Name = name
	} else {
		policy.Name = res.Name
	}

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

func (b *Builder) buildOrgPolicy(ref string, res *resolver.ResolvedResource) {
	orgPolicy := &OrgPolicy{
		TFName: res.Name,
	}

	if name := b.getAttrAsString(res, "name"); name != "" {
		orgPolicy.Name = name
	}

	if policyType := b.getAttrAsString(res, "type"); policyType != "" {
		orgPolicy.PolicyType = policyType
	} else {
		orgPolicy.PolicyType = "SERVICE_CONTROL_POLICY"
	}

	if content := b.getAttrAsString(res, "content"); content != "" {
		doc, err := ParsePolicyDocument(content)
		if err != nil {
			b.warnings = append(b.warnings, fmt.Sprintf(
				"org policy %q: failed to parse policy document: %v", res.Name, err))
		} else {
			orgPolicy.Policy = doc
			orgPolicy.AllowActions = doc.GetAllActions()
			orgPolicy.DenyActions = doc.GetDeniedActions()
			for _, stmt := range doc.Statements {
				if stmt.IsAllow() && len(stmt.NotActions) > 0 {
					orgPolicy.AllowNotActions = append(orgPolicy.AllowNotActions, stmt.NotActions...)
				}
			}
		}
	}

	b.config.OrgPolicies = append(b.config.OrgPolicies, orgPolicy)
}

func (b *Builder) handlePublicAccessBlock(res *resolver.ResolvedResource) {
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

	bucketName := strings.TrimPrefix(bucketRef, "aws_s3_bucket.")
	for _, bucket := range b.config.Buckets {
		if bucket.TFName == bucketName {
			bucket.BPABlockPublicACLs = b.getAttrAsBool(res, "block_public_acls")
			bucket.BPAIgnorePublicACLs = b.getAttrAsBool(res, "ignore_public_acls")
			bucket.BPABlockPublicPolicy = b.getAttrAsBool(res, "block_public_policy")
			bucket.BPARestrictPublicBuckets = b.getAttrAsBool(res, "restrict_public_buckets")
			break
		}
	}
}

// handleRolePolicyAttachment updates the corresponding role's HasRolePolicy flag.
func (b *Builder) handleRolePolicyAttachment(res *resolver.ResolvedResource) {
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

	policyRef := ""
	for _, r := range res.References {
		if strings.HasPrefix(r, "aws_iam_policy.") {
			policyRef = r
			break
		}
	}

	managedPolicyARN := b.getAttrAsString(res, "policy_arn")

	roleName := strings.TrimPrefix(roleRef, "aws_iam_role.")
	for _, role := range b.config.Roles {
		if role.TFName == roleName {
			role.HasRolePolicy = true

			if policyRef != "" {
				policyName := strings.TrimPrefix(policyRef, "aws_iam_policy.")
				if p := b.config.GetPolicyByTFName(policyName); p != nil && p.Policy != nil {
					role.RolePolicyActions = append(role.RolePolicyActions, p.Policy.GetAllActions()...)
					role.RoleDenyActions = append(role.RoleDenyActions, p.Policy.GetDeniedActions()...)
					mergePerBucketActions(role.IdentityAllowActionsPerBucket, p.Policy.GetAllowActionsPerBucket())
					for _, stmt := range p.Policy.Statements {
						if stmt.IsAllow() && len(stmt.NotActions) > 0 {
							role.HasRoleNotAction = true
							role.RoleNotActions = append(role.RoleNotActions, stmt.NotActions...)
						}
					}
				}
			} else if actions := ManagedPolicyS3Actions(managedPolicyARN); len(actions) > 0 {
				role.RolePolicyActions = append(role.RolePolicyActions, actions...)
				mergePerBucketActions(role.IdentityAllowActionsPerBucket, map[string][]string{"*": actions})
			}
			break
		}
	}
}

// linkResources establishes relationships between resources.
func (b *Builder) linkResources() {
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
					role.RoleDenyActions = append(role.RoleDenyActions, rp.Policy.GetDeniedActions()...)
					mergePerBucketActions(role.IdentityAllowActionsPerBucket, rp.Policy.GetAllowActionsPerBucket())
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

	for _, up := range b.config.UserPolicies {
		if up.UserRef == "" {
			continue
		}
		userName := strings.TrimPrefix(up.UserRef, "aws_iam_user.")
		for _, user := range b.config.Users {
			if user.TFName == userName {
				user.HasUserPolicy = true
				if up.Policy != nil {
					user.UserPolicyActions = append(user.UserPolicyActions, up.Policy.GetAllActions()...)
					user.UserDenyActions = append(user.UserDenyActions, up.Policy.GetDeniedActions()...)
					mergePerBucketActions(user.IdentityAllowActionsPerBucket, up.Policy.GetAllowActionsPerBucket())
					for _, stmt := range up.Policy.Statements {
						if stmt.IsAllow() && len(stmt.NotActions) > 0 {
							user.HasUserNotAction = true
							user.UserNotActions = append(user.UserNotActions, stmt.NotActions...)
						}
					}
				}
				break
			}
		}
	}

	for _, role := range b.config.Roles {
		if role.BoundaryRef == "" {
			continue
		}
		policyName := strings.TrimPrefix(role.BoundaryRef, "aws_iam_policy.")
		if p := b.config.GetPolicyByTFName(policyName); p != nil && p.Policy != nil {
			role.BoundaryActions = p.Policy.GetAllActions()
			mergePerBucketActions(role.BoundaryActionsPerBucket, p.Policy.GetAllowActionsPerBucket())
		}
	}

	for _, user := range b.config.Users {
		if user.BoundaryRef == "" {
			continue
		}
		policyName := strings.TrimPrefix(user.BoundaryRef, "aws_iam_policy.")
		if p := b.config.GetPolicyByTFName(policyName); p != nil && p.Policy != nil {
			user.BoundaryActions = p.Policy.GetAllActions()
			mergePerBucketActions(user.BoundaryActionsPerBucket, p.Policy.GetAllowActionsPerBucket())
		}
	}

	b.detectCrossAccount()
}

func (b *Builder) detectCrossAccount() {
	localAccounts := b.collectLocalAccountIDs()

	arnAccountRe := regexp.MustCompile(`arn:aws[^:]*:iam::(\d+):`)

	for _, role := range b.config.Roles {
		if role.AssumeRolePolicy == nil {
			continue
		}
		for _, stmt := range role.AssumeRolePolicy.Statements {
			for _, p := range stmt.Principals {
				match := arnAccountRe.FindStringSubmatch(p.Value)
				if len(match) < 2 {
					continue
				}
				accountID := match[1]
				if len(localAccounts) == 0 || !localAccounts[accountID] {
					role.CrossAccount = true
					break
				}
			}
			if role.CrossAccount {
				break
			}
		}
	}
}

// collectLocalAccountIDs extracts AWS account IDs from ARNs found in role
// assume-role policies and policy ARN attributes within the current config.
func (b *Builder) collectLocalAccountIDs() map[string]bool {
	ids := make(map[string]bool)
	arnAccountRe := regexp.MustCompile(`arn:aws[^:]*:iam::(\d+):`)

	// Look for account IDs in role assume-role policies (trust policies).
	for _, role := range b.config.Roles {
		if role.AssumeRolePolicy == nil {
			continue
		}
		for _, stmt := range role.AssumeRolePolicy.Statements {
			for _, p := range stmt.Principals {
				if m := arnAccountRe.FindStringSubmatch(p.Value); len(m) >= 2 {
					ids[m[1]] = true
				}
			}
		}
	}

	// Look for account IDs in standalone policy ARNs.
	for _, p := range b.config.Policies {
		if m := arnAccountRe.FindStringSubmatch(p.ARN); len(m) >= 2 {
			ids[m[1]] = true
		}
	}

	return ids
}

func (b *Builder) getAttrAsString(res *resolver.ResolvedResource, name string) string {
	if val, ok := res.Attributes[name]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func (b *Builder) getAttrAsBool(res *resolver.ResolvedResource, name string) bool {
	if val, ok := res.Attributes[name]; ok {
		if bv, ok := val.(bool); ok {
			return bv
		}
	}
	return false
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

// looksLikeUnresolvedRef returns true when s is not valid JSON because it
// contains Terraform variable/resource references that were not evaluated.
// Examples: `data.aws_iam_policy_document.x.json`, `aws_iam_role.x.arn`,
// or any JSON-like string containing `${...}` template expressions.
func looksLikeUnresolvedRef(s string) bool {
	if strings.Contains(s, "${") {
		return true
	}
	if strings.HasPrefix(s, "data.") || strings.HasPrefix(s, "var.") || strings.HasPrefix(s, "local.") {
		return true
	}
	if strings.HasPrefix(s, "aws_") {
		return true
	}
	return false
}

// extractResourceRef extracts a resource reference from various formats.
func extractResourceRef(s string) string {
	re := regexp.MustCompile(`(aws_[a-z0-9_]+)\.([a-z0-9_]+)`)
	matches := re.FindStringSubmatch(s)
	if len(matches) >= 3 {
		return matches[1] + "." + matches[2]
	}
	return ""
}

// mergePerBucketActions merges src into dst, deduplicating actions per bucket key.
func mergePerBucketActions(dst, src map[string][]string) {
	for bucket, actions := range src {
		seen := make(map[string]bool, len(dst[bucket]))
		for _, a := range dst[bucket] {
			seen[a] = true
		}
		for _, a := range actions {
			if !seen[a] {
				seen[a] = true
				dst[bucket] = append(dst[bucket], a)
			}
		}
	}
}

func BuildFromResources(resources map[string]*resolver.ResolvedResource, graph *resolver.DependencyGraph) (*Config, []string, error) {
	b := NewBuilder(resources, graph)
	config, err := b.Build()
	return config, b.Warnings(), err
}

// registerServicePrincipal adds a service principal to the config (deduplicated).
func (b *Builder) registerServicePrincipal(name string) {
	for _, sp := range b.config.ServicePrincipals {
		if sp.Name == name {
			return
		}
	}
	// Build an Alloy-safe TFName: replace dots and hyphens with underscores.
	tfName := strings.ReplaceAll(name, ".", "_")
	tfName = strings.ReplaceAll(tfName, "-", "_")
	b.config.ServicePrincipals = append(b.config.ServicePrincipals, &ServicePrincipal{
		TFName: tfName,
		Name:   name,
	})
}
