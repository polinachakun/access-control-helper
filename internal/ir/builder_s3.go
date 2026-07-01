package ir

import (
	"fmt"
	"strings"

	"access-control-helper/internal/resolver"
)

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
