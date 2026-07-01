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
		case "aws_iam_user_policy_attachment":
			b.handleUserPolicyAttachment(res)
		}
	}

	// Third pass: link attachments and update flags
	b.linkResources()

	return b.config, nil
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
