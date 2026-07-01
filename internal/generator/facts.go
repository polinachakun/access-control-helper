package generator

import (
	"fmt"
	"sort"
	"strings"

	"access-control-helper/internal/ir"
)

// buildConfigFacts generates the body of the ConfigFacts fact block.
func (g *Generator) buildConfigFacts() string {
	var sb strings.Builder

	// ── S3 Buckets ────────────────────────────────────────────────────────
	for _, b := range g.config.Buckets {
		sig := "bucket_" + AlloyID(b.TFName)
		envTag := tagOrDefault(b.EnvTag, "TAG_DEV")
		sb.WriteString(fmt.Sprintf("  %s.envTag                = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.blockPublicACLs       = %s\n", sig, BoolToAlloy(b.BPABlockPublicACLs)))
		sb.WriteString(fmt.Sprintf("  %s.ignorePublicACLs      = %s\n", sig, BoolToAlloy(b.BPAIgnorePublicACLs)))
		sb.WriteString(fmt.Sprintf("  %s.blockPublicPolicy     = %s\n", sig, BoolToAlloy(b.BPABlockPublicPolicy)))
		sb.WriteString(fmt.Sprintf("  %s.restrictPublicBuckets = %s\n", sig, BoolToAlloy(b.BPARestrictPublicBuckets)))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn             = none\n\n", sig))
	}

	// ── Bucket Policies ───────────────────────────────────────────────────
	for _, p := range g.config.BucketPolicies {
		sig := "policy_" + AlloyID(p.TFName)

		bucketSig := "none"
		if p.BucketRef != "" {
			bucketName := strings.TrimPrefix(p.BucketRef, "aws_s3_bucket.")
			bucketSig = "bucket_" + AlloyID(bucketName)
		}

		denyAllExcept := "none"
		if p.DenyVpceID != "" {
			denyAllExcept = VpceToAlloyID(p.DenyVpceID)
		}

		allowPrincipal := "none"
		for _, prin := range p.AllowPrincipals {
			if sig := resolvePrincipalSig(prin, g.config); sig != "" {
				allowPrincipal = sig
				break
			}
		}

		denyPrincipal := "none"
		for _, prin := range p.DenyPrincipals {
			if sig := resolvePrincipalSig(prin, g.config); sig != "" {
				denyPrincipal = sig
				break
			}
		}

		allowAnyPrincipal := "False"
		if p.AllowAnyPrincipal {
			allowAnyPrincipal = "True"
		}

		denyAnyPrincipal := "False"
		if p.DenyAnyPrincipal {
			denyAnyPrincipal = "True"
		}

		allowBucketResource := "False"
		if p.AllowBucketResource {
			allowBucketResource = "True"
		}

		allowObjectResource := "False"
		if p.AllowObjectResource {
			allowObjectResource = "True"
		}

		denyBucketResource := "False"
		if p.DenyBucketResource {
			denyBucketResource = "True"
		}

		denyObjectResource := "False"
		if p.DenyObjectResource {
			denyObjectResource = "True"
		}

		allowActions := toAlloyActionSet(p.AllowActions)
		allowNotActions := toAlloyActionSet(p.AllowNotActions)
		denyActions := toAlloyActionSet(p.DenyActions)
		denyNotActions := toAlloyActionSet(p.DenyNotActions)

		sb.WriteString(fmt.Sprintf("  %s.bucket              = %s\n", sig, bucketSig))
		sb.WriteString(fmt.Sprintf("  %s.denyAllExcept       = %s\n", sig, denyAllExcept))
		sb.WriteString(fmt.Sprintf("  %s.allowPrincipal      = %s\n", sig, allowPrincipal))
		sb.WriteString(fmt.Sprintf("  %s.allowAnyPrincipal   = %s\n", sig, allowAnyPrincipal))
		sb.WriteString(fmt.Sprintf("  %s.allowActions        = %s\n", sig, allowActions))
		sb.WriteString(fmt.Sprintf("  %s.allowNotActions     = %s\n", sig, allowNotActions))
		sb.WriteString(fmt.Sprintf("  %s.hasAllowNotAction   = %s\n", sig, BoolToAlloy(p.HasAllowNotAction)))
		sb.WriteString(fmt.Sprintf("  %s.allowBucketResource = %s\n", sig, allowBucketResource))
		sb.WriteString(fmt.Sprintf("  %s.allowObjectResource = %s\n", sig, allowObjectResource))
		sb.WriteString(fmt.Sprintf("  %s.denyActions         = %s\n", sig, denyActions))
		sb.WriteString(fmt.Sprintf("  %s.denyNotActions      = %s\n", sig, denyNotActions))
		sb.WriteString(fmt.Sprintf("  %s.hasDenyNotAction    = %s\n", sig, BoolToAlloy(p.HasDenyNotAction)))
		sb.WriteString(fmt.Sprintf("  %s.denyPrincipal       = %s\n", sig, denyPrincipal))
		sb.WriteString(fmt.Sprintf("  %s.denyAnyPrincipal    = %s\n", sig, denyAnyPrincipal))
		sb.WriteString(fmt.Sprintf("  %s.denyBucketResource  = %s\n", sig, denyBucketResource))
		sb.WriteString(fmt.Sprintf("  %s.denyObjectResource  = %s\n", sig, denyObjectResource))
		sb.WriteString(fmt.Sprintf("  %s.abacCondition       = %s\n", sig, BoolToAlloy(p.HasABAC)))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn           = %s\n\n", sig, bucketSig))
	}

	// ── OrgRCPs ───────────────────────────────────────────────────────────
	for _, rcp := range g.config.RCPs() {
		sig := "rcp_" + AlloyID(rcp.TFName)
		allowA := toAlloyActionSet(rcp.AllowActions)
		allowNotA := toAlloyActionSet(rcp.AllowNotActions)
		denyA := toAlloyActionSet(rcp.DenyActions)
		sb.WriteString(fmt.Sprintf("  %s.rcpAllowActions    = %s\n", sig, allowA))
		sb.WriteString(fmt.Sprintf("  %s.rcpAllowNotActions = %s\n", sig, allowNotA))
		sb.WriteString(fmt.Sprintf("  %s.rcpDenyActions     = %s\n", sig, denyA))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn          = none\n\n", sig))
	}

	// ── OrgSCPs ───────────────────────────────────────────────────────────
	for _, scp := range g.config.SCPs() {
		sig := "scp_" + AlloyID(scp.TFName)
		allowA := toAlloyActionSet(scp.AllowActions)
		allowNotA := toAlloyActionSet(scp.AllowNotActions)
		denyA := toAlloyActionSet(scp.DenyActions)
		sb.WriteString(fmt.Sprintf("  %s.scpAllowActions    = %s\n", sig, allowA))
		sb.WriteString(fmt.Sprintf("  %s.scpAllowNotActions = %s\n", sig, allowNotA))
		sb.WriteString(fmt.Sprintf("  %s.scpDenyActions     = %s\n", sig, denyA))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn          = none\n\n", sig))
	}

	// ── IAM Roles ─────────────────────────────────────────────────────────
	for _, r := range g.config.Roles {
		sig := "role_" + AlloyID(r.TFName)
		envTag := tagOrDefault(r.EnvTag, "TAG_DEV")
		roleDenyActions := toAlloyActionSet(r.RoleDenyActions)
		roleNotActions := toAlloyActionSet(r.RoleNotActions)
		// Session policies are sts:AssumeRole runtime parameters — not in Terraform source.
		sessionActions := toAlloyActionSet(nil)

		sb.WriteString(fmt.Sprintf("  %s.envTag               = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.crossAccount         = %s\n", sig, BoolToAlloy(r.CrossAccount)))
		sb.WriteString(fmt.Sprintf("  %s.hasIdentityPolicy    = %s\n", sig, BoolToAlloy(r.HasRolePolicy)))
		sb.WriteString(fmt.Sprintf("  %s.identityAllowedOn    = %s\n", sig, g.buildIdentityAllowedOnRelation(r.IdentityAllowActionsPerBucket)))
		sb.WriteString(fmt.Sprintf("  %s.identityDenyActions  = %s\n", sig, roleDenyActions))
		sb.WriteString(fmt.Sprintf("  %s.identityNotActions   = %s\n", sig, roleNotActions))
		sb.WriteString(fmt.Sprintf("  %s.hasNotAction         = %s\n", sig, BoolToAlloy(r.HasRoleNotAction)))
		sb.WriteString(fmt.Sprintf("  %s.hasBoundary          = %s\n", sig, BoolToAlloy(r.HasBoundary)))
		sb.WriteString(fmt.Sprintf("  %s.boundaryAllowedOn    = %s\n", sig, g.buildIdentityAllowedOnRelation(r.BoundaryActionsPerBucket)))
		sb.WriteString(fmt.Sprintf("  %s.hasSessionPolicy     = %s\n", sig, BoolToAlloy(r.HasSessionPolicy)))
		sb.WriteString(fmt.Sprintf("  %s.sessionPolicyActions = %s\n", sig, sessionActions))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn            = none\n\n", sig))
	}

	// ── IAM Users ─────────────────────────────────────────────────────────
	for _, u := range g.config.Users {
		sig := "user_" + AlloyID(u.TFName)
		envTag := tagOrDefault(u.EnvTag, "TAG_DEV")
		userDenyActions := toAlloyActionSet(u.UserDenyActions)
		userNotActions := toAlloyActionSet(u.UserNotActions)

		sb.WriteString(fmt.Sprintf("  %s.envTag               = %s\n", sig, envTag))
		sb.WriteString(fmt.Sprintf("  %s.crossAccount         = %s\n", sig, BoolToAlloy(false)))
		sb.WriteString(fmt.Sprintf("  %s.hasIdentityPolicy    = %s\n", sig, BoolToAlloy(u.HasUserPolicy)))
		sb.WriteString(fmt.Sprintf("  %s.identityAllowedOn    = %s\n", sig, g.buildIdentityAllowedOnRelation(u.IdentityAllowActionsPerBucket)))
		sb.WriteString(fmt.Sprintf("  %s.identityDenyActions  = %s\n", sig, userDenyActions))
		sb.WriteString(fmt.Sprintf("  %s.identityNotActions   = %s\n", sig, userNotActions))
		sb.WriteString(fmt.Sprintf("  %s.hasNotAction         = %s\n", sig, BoolToAlloy(u.HasUserNotAction)))
		sb.WriteString(fmt.Sprintf("  %s.hasBoundary          = %s\n", sig, BoolToAlloy(u.HasBoundary)))
		sb.WriteString(fmt.Sprintf("  %s.boundaryAllowedOn    = %s\n", sig, g.buildIdentityAllowedOnRelation(u.BoundaryActionsPerBucket)))
		// Session policies are runtime sts:AssumeRole parameters; not applicable to IAM users.
		sb.WriteString(fmt.Sprintf("  %s.hasSessionPolicy     = %s\n", sig, BoolToAlloy(false)))
		sb.WriteString(fmt.Sprintf("  %s.sessionPolicyActions = %s\n", sig, toAlloyActionSet(nil)))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn            = none\n\n", sig))
	}

	// ── Service Principals ────────────────────────────────────────────────
	for _, sp := range g.config.ServicePrincipals {
		sig := "svc_" + AlloyID(sp.TFName)
		sb.WriteString(fmt.Sprintf("  %s.envTag               = TAG_DEV\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.crossAccount         = False\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.hasIdentityPolicy    = False\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.identityAllowedOn    = none -> none\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.identityDenyActions  = none\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.identityNotActions   = none\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.hasNotAction         = False\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.hasBoundary          = False\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.boundaryAllowedOn    = none -> none\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.hasSessionPolicy     = False\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.sessionPolicyActions = none\n", sig))
		sb.WriteString(fmt.Sprintf("  %s.dependsOn            = none\n\n", sig))
	}

	// ── Actions ───────────────────────────────────────────────────────────
	for _, action := range g.sortedKeys(g.actions) {
		bucketLevel, objectLevel := actionLevelFacts(action)
		sb.WriteString(fmt.Sprintf("  %s.bucketLevel = %s\n", action, bucketLevel))
		sb.WriteString(fmt.Sprintf("  %s.objectLevel = %s\n\n", action, objectLevel))
	}

	return sb.String()
}

func toAlloyActionSet(actions []string) string {
	if HasWildcardActions(actions) {
		return "Action"
	}
	expanded := ExpandAnalyzableActions(actions)
	if len(expanded) == 0 {
		return "none"
	}
	ids := make([]string, 0, len(expanded))
	for _, a := range expanded {
		ids = append(ids, ActionToAlloyID(a))
	}
	return FormatAlloySet(ids)
}

// tagOrDefault converts an environment tag to its Alloy identifier,
// or returns the default when the tag is empty.
func tagOrDefault(tag, defaultTag string) string {
	if tag == "" {
		return defaultTag
	}
	return TagToAlloyID(tag)
}

func resolvePrincipalSig(principal string, config *ir.Config) string {

	for _, sp := range config.ServicePrincipals {
		if principal == sp.Name {
			return "svc_" + AlloyID(sp.TFName)
		}
	}

	// Direct Terraform reference: "aws_iam_role.name" or "aws_iam_user.name"
	if strings.HasPrefix(principal, "aws_iam_role.") {
		parts := strings.Split(principal, ".")
		if len(parts) >= 2 {
			return "role_" + AlloyID(parts[1])
		}
	}
	if strings.HasPrefix(principal, "aws_iam_user.") {
		parts := strings.Split(principal, ".")
		if len(parts) >= 2 {
			return "user_" + AlloyID(parts[1])
		}
	}

	for _, prefix := range []string{"${aws_iam_role.", "${aws_iam_user."} {
		if strings.Contains(principal, prefix) {
			start := strings.Index(principal, prefix) + len(prefix)
			end := strings.Index(principal[start:], ".")
			if end > 0 {
				name := principal[start : start+end]
				if strings.Contains(prefix, "role") {
					return "role_" + AlloyID(name)
				}
				return "user_" + AlloyID(name)
			}
		}
	}

	for _, r := range config.Roles {
		if strings.Contains(principal, r.Name) || strings.Contains(principal, r.TFName) {
			return "role_" + AlloyID(r.TFName)
		}
	}
	for _, u := range config.Users {
		if strings.Contains(principal, u.Name) || strings.Contains(principal, u.TFName) {
			return "user_" + AlloyID(u.TFName)
		}
	}
	return ""
}

// buildIdentityAllowedOnRelation converts the per-bucket action map from IR into an
// Alloy relation expression for the identityAllowedOn field.
// perBucketActions keys are actual S3 bucket names (from ARNs) or bucket TFNames;
// the special key "*" means actions apply to all buckets.
// A wildcard action (s3:*) maps to the full Action universe in Alloy.
func (g *Generator) buildIdentityAllowedOnRelation(perBucketActions map[string][]string) string {
	if len(perBucketActions) == 0 {
		return "none -> none"
	}

	wildcardActions := perBucketActions["*"]
	wildcardCoversAll := HasWildcardActions(wildcardActions)

	type entry struct {
		bucketSig  string
		actionExpr string
	}

	var entries []entry
	for _, b := range g.config.Buckets {
		bucketSig := "bucket_" + AlloyID(b.TFName)

		if wildcardCoversAll {
			entries = append(entries, entry{bucketSig: bucketSig, actionExpr: "Action"})
			continue
		}

		actionSet := make(map[string]bool)
		for _, a := range ExpandAnalyzableActions(wildcardActions) {
			actionSet[ActionToAlloyID(a)] = true
		}

		bucketHasWildcard := false
		for _, key := range []string{b.BucketName, b.TFName} {
			if key == "" || key == "*" {
				continue
			}
			if specific, ok := perBucketActions[key]; ok {
				if HasWildcardActions(specific) {
					bucketHasWildcard = true
					break
				}
				for _, a := range ExpandAnalyzableActions(specific) {
					actionSet[ActionToAlloyID(a)] = true
				}
			}
		}

		if bucketHasWildcard {
			entries = append(entries, entry{bucketSig: bucketSig, actionExpr: "Action"})
			continue
		}

		if len(actionSet) == 0 {
			continue
		}

		var actionIDs []string
		for id := range actionSet {
			actionIDs = append(actionIDs, id)
		}
		sort.Strings(actionIDs)
		entries = append(entries, entry{
			bucketSig:  bucketSig,
			actionExpr: FormatAlloySet(actionIDs),
		})
	}

	if len(entries) == 0 {
		return "none -> none"
	}

	parts := make([]string, len(entries))
	for i, e := range entries {
		parts[i] = fmt.Sprintf("%s -> (%s)", e.bucketSig, e.actionExpr)
	}
	return strings.Join(parts, " +\n    ")
}
