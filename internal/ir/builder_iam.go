package ir

import (
	"fmt"
	"strings"

	"access-control-helper/internal/resolver"
)

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

// handleUserPolicyAttachment updates the corresponding user's HasUserPolicy flag
// and resolves the attached policy document or well-known managed policy ARN.
func (b *Builder) handleUserPolicyAttachment(res *resolver.ResolvedResource) {
	userRef := ""
	if user := b.getAttrAsString(res, "user"); user != "" {
		userRef = extractResourceRef(user)
	}
	if userRef == "" {
		for _, r := range res.References {
			if strings.HasPrefix(r, "aws_iam_user.") {
				userRef = r
				break
			}
		}
	}

	if userRef == "" {
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

	userName := strings.TrimPrefix(userRef, "aws_iam_user.")
	for _, user := range b.config.Users {
		if user.TFName == userName {
			user.HasUserPolicy = true

			if policyRef != "" {
				policyName := strings.TrimPrefix(policyRef, "aws_iam_policy.")
				if p := b.config.GetPolicyByTFName(policyName); p != nil && p.Policy != nil {
					user.UserPolicyActions = append(user.UserPolicyActions, p.Policy.GetAllActions()...)
					user.UserDenyActions = append(user.UserDenyActions, p.Policy.GetDeniedActions()...)
					mergePerBucketActions(user.IdentityAllowActionsPerBucket, p.Policy.GetAllowActionsPerBucket())
					for _, stmt := range p.Policy.Statements {
						if stmt.IsAllow() && len(stmt.NotActions) > 0 {
							user.HasUserNotAction = true
							user.UserNotActions = append(user.UserNotActions, stmt.NotActions...)
						}
					}
				}
			} else if actions := ManagedPolicyS3Actions(managedPolicyARN); len(actions) > 0 {
				user.UserPolicyActions = append(user.UserPolicyActions, actions...)
				mergePerBucketActions(user.IdentityAllowActionsPerBucket, map[string][]string{"*": actions})
			}
			break
		}
	}
}
