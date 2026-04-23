package unit_test

import (
	"testing"

	"access-control-helper/internal/ir"
	"access-control-helper/internal/resolver"
)

func makeResources(entries ...func() (string, *resolver.ResolvedResource)) map[string]*resolver.ResolvedResource {
	m := make(map[string]*resolver.ResolvedResource)
	for _, e := range entries {
		k, v := e()
		m[k] = v
	}
	return m
}

func bucket(tfName, envTag string) func() (string, *resolver.ResolvedResource) {
	return func() (string, *resolver.ResolvedResource) {
		attrs := map[string]interface{}{
			"bucket": tfName + "-id",
		}
		if envTag != "" {
			attrs["tags"] = map[string]interface{}{"environment": envTag}
		}
		return "aws_s3_bucket." + tfName, &resolver.ResolvedResource{
			Type:       "aws_s3_bucket",
			Name:       tfName,
			Attributes: attrs,
		}
	}
}

func role(tfName, name, envTag string) func() (string, *resolver.ResolvedResource) {
	return func() (string, *resolver.ResolvedResource) {
		attrs := map[string]interface{}{
			"name": name,
		}
		if envTag != "" {
			attrs["tags"] = map[string]interface{}{"environment": envTag}
		}
		return "aws_iam_role." + tfName, &resolver.ResolvedResource{
			Type:       "aws_iam_role",
			Name:       tfName,
			Attributes: attrs,
		}
	}
}

func iamPolicy(tfName, name, policyJSON string) func() (string, *resolver.ResolvedResource) {
	return func() (string, *resolver.ResolvedResource) {
		return "aws_iam_policy." + tfName, &resolver.ResolvedResource{
			Type: "aws_iam_policy",
			Name: tfName,
			Attributes: map[string]interface{}{
				"name":   name,
				"policy": policyJSON,
			},
		}
	}
}

func policyAttachment(tfName, roleTF, policyTF string) func() (string, *resolver.ResolvedResource) {
	return func() (string, *resolver.ResolvedResource) {
		return "aws_iam_role_policy_attachment." + tfName, &resolver.ResolvedResource{
			Type: "aws_iam_role_policy_attachment",
			Name: tfName,
			Attributes: map[string]interface{}{
				"role": "aws_iam_role." + roleTF + ".name",
			},
			References: []string{
				"aws_iam_role." + roleTF,
				"aws_iam_policy." + policyTF,
			},
		}
	}
}

func build(t *testing.T, entries ...func() (string, *resolver.ResolvedResource)) *ir.Config {
	t.Helper()
	resources := makeResources(entries...)
	config, err := ir.BuildFromResources(resources, nil)
	if err != nil {
		t.Fatalf("BuildFromResources failed: %v", err)
	}
	return config
}

func TestBuilder_S3Bucket_BasicFields(t *testing.T) {
	config := build(t, bucket("my_bucket", "prod"))

	if len(config.Buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(config.Buckets))
	}
	b := config.Buckets[0]
	if b.TFName != "my_bucket" {
		t.Errorf("TFName = %q, want my_bucket", b.TFName)
	}
	if b.EnvTag != "prod" {
		t.Errorf("EnvTag = %q, want prod", b.EnvTag)
	}
}

func TestBuilder_S3Bucket_NoTag(t *testing.T) {
	config := build(t, bucket("bare_bucket", ""))

	b := config.Buckets[0]
	if b.EnvTag != "" {
		t.Errorf("EnvTag should be empty when no tags, got %q", b.EnvTag)
	}
}

func TestBuilder_S3Bucket_PublicAccessBlock(t *testing.T) {
	config := build(t,
		bucket("my_bucket", "prod"),
		func() (string, *resolver.ResolvedResource) {
			return "aws_s3_bucket_public_access_block.my_bucket", &resolver.ResolvedResource{
				Type: "aws_s3_bucket_public_access_block",
				Name: "my_bucket_bpa",
				Attributes: map[string]interface{}{
					"bucket": "aws_s3_bucket.my_bucket.id",
				},
				References: []string{"aws_s3_bucket.my_bucket"},
			}
		},
	)

	b := config.GetBucketByTFName("my_bucket")
	if b == nil {
		t.Fatal("bucket not found")
	}
	if !b.HasBPA {
		t.Error("HasBPA should be true when public access block is configured")
	}
}

func TestBuilder_IAMRole_BasicFields(t *testing.T) {
	config := build(t, role("app_role", "app-role", "prod"))

	if len(config.Roles) != 1 {
		t.Fatalf("expected 1 role, got %d", len(config.Roles))
	}
	r := config.Roles[0]
	if r.TFName != "app_role" {
		t.Errorf("TFName = %q, want app_role", r.TFName)
	}
	if r.Name != "app-role" {
		t.Errorf("Name = %q, want app-role", r.Name)
	}
	if r.EnvTag != "prod" {
		t.Errorf("EnvTag = %q, want prod", r.EnvTag)
	}
}

func TestBuilder_IAMRole_NoRolePolicyByDefault(t *testing.T) {
	config := build(t, role("app_role", "app-role", "prod"))

	r := config.Roles[0]
	if r.HasRolePolicy {
		t.Error("HasRolePolicy should be false when no policy is attached")
	}
	if len(r.RolePolicyActions) != 0 {
		t.Errorf("RolePolicyActions should be empty, got %v", r.RolePolicyActions)
	}
}

func TestBuilder_PolicyAttachment_PropagatesActions(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}`

	config := build(t,
		role("app_role", "app-role", "prod"),
		iamPolicy("s3_read", "s3-read", policyJSON),
		policyAttachment("attach", "app_role", "s3_read"),
	)

	r := config.GetRoleByTFName("app_role")
	if r == nil {
		t.Fatal("role not found")
	}
	if !r.HasRolePolicy {
		t.Error("HasRolePolicy should be true after attachment")
	}
	if len(r.RolePolicyActions) == 0 {
		t.Error("RolePolicyActions should be populated from attached policy")
	}

	actions := make(map[string]bool)
	for _, a := range r.RolePolicyActions {
		actions[a] = true
	}
	if !actions["s3:GetObject"] {
		t.Error("s3:GetObject should be in RolePolicyActions")
	}
	if !actions["s3:ListBucket"] {
		t.Error("s3:ListBucket should be in RolePolicyActions")
	}
}

func TestBuilder_PolicyAttachment_PropagatesDenyActions(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:DeleteObject"],"Resource":"*"}]}`

	config := build(t,
		role("app_role", "app-role", "prod"),
		iamPolicy("deny_delete", "deny-delete", policyJSON),
		policyAttachment("attach", "app_role", "deny_delete"),
	)

	r := config.GetRoleByTFName("app_role")
	if len(r.RoleDenyActions) == 0 {
		t.Error("RoleDenyActions should be populated from Deny statement in attached policy")
	}
	found := false
	for _, a := range r.RoleDenyActions {
		if a == "s3:DeleteObject" {
			found = true
		}
	}
	if !found {
		t.Errorf("s3:DeleteObject should be in RoleDenyActions, got %v", r.RoleDenyActions)
	}
}

func TestBuilder_PolicyAttachment_PropagatesNotActions(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["s3:DeleteObject"],"Resource":"*"}]}`

	config := build(t,
		role("app_role", "app-role", "prod"),
		iamPolicy("not_delete", "not-delete", policyJSON),
		policyAttachment("attach", "app_role", "not_delete"),
	)

	r := config.GetRoleByTFName("app_role")
	if !r.HasRoleNotAction {
		t.Error("HasRoleNotAction should be true when Allow uses NotAction")
	}
	found := false
	for _, a := range r.RoleNotActions {
		if a == "s3:DeleteObject" {
			found = true
		}
	}
	if !found {
		t.Errorf("s3:DeleteObject should be in RoleNotActions, got %v", r.RoleNotActions)
	}
}

func TestBuilder_PermissionBoundary_LinkedToRole(t *testing.T) {
	boundaryJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`

	config := build(t,
		func() (string, *resolver.ResolvedResource) {
			return "aws_iam_role.restricted_role", &resolver.ResolvedResource{
				Type: "aws_iam_role",
				Name: "restricted_role",
				Attributes: map[string]interface{}{
					"name":                 "restricted-role",
					"permissions_boundary": "aws_iam_policy.boundary.arn",
				},
				References: []string{"aws_iam_policy.boundary"},
			}
		},
		iamPolicy("boundary", "s3-get-only", boundaryJSON),
	)

	r := config.GetRoleByTFName("restricted_role")
	if r == nil {
		t.Fatal("role not found")
	}
	if !r.HasBoundary {
		t.Error("HasBoundary should be true when permissions_boundary is set")
	}
	if len(r.BoundaryActions) == 0 {
		t.Error("BoundaryActions should be populated from boundary policy")
	}
	found := false
	for _, a := range r.BoundaryActions {
		if a == "s3:GetObject" {
			found = true
		}
	}
	if !found {
		t.Errorf("s3:GetObject should be in BoundaryActions, got %v", r.BoundaryActions)
	}
}

func TestBuilder_BucketPolicy_AllowStatement(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:role/app-role"},"Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::my-bucket","arn:aws:s3:::my-bucket/*"]}]}`

	config := build(t,
		bucket("my_bucket", "prod"),
		func() (string, *resolver.ResolvedResource) {
			return "aws_s3_bucket_policy.my_bucket", &resolver.ResolvedResource{
				Type: "aws_s3_bucket_policy",
				Name: "my_bucket_policy",
				Attributes: map[string]interface{}{
					"bucket": "aws_s3_bucket.my_bucket.id",
					"policy": policyJSON,
				},
				References: []string{"aws_s3_bucket.my_bucket"},
			}
		},
	)

	if len(config.BucketPolicies) == 0 {
		t.Fatal("expected at least one bucket policy")
	}
	p := config.BucketPolicies[0]
	if len(p.AllowActions) == 0 {
		t.Error("AllowActions should be populated from Allow statement")
	}
	if p.AllowAnyPrincipal {
		t.Error("AllowAnyPrincipal should be false for specific principal")
	}
	if len(p.AllowPrincipals) == 0 {
		t.Error("AllowPrincipals should contain the principal ARN")
	}
}

func TestBuilder_BucketPolicy_VPCEDeny(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"aws:sourceVpce":"vpce-0abc1234"}}}]}`

	config := build(t,
		bucket("my_bucket", "prod"),
		func() (string, *resolver.ResolvedResource) {
			return "aws_s3_bucket_policy.my_bucket", &resolver.ResolvedResource{
				Type: "aws_s3_bucket_policy",
				Name: "my_bucket_policy",
				Attributes: map[string]interface{}{
					"bucket": "aws_s3_bucket.my_bucket.id",
					"policy": policyJSON,
				},
				References: []string{"aws_s3_bucket.my_bucket"},
			}
		},
	)

	if len(config.BucketPolicies) == 0 {
		t.Fatal("expected at least one bucket policy")
	}
	p := config.BucketPolicies[0]
	if p.DenyVpceID != "vpce-0abc1234" {
		t.Errorf("DenyVpceID = %q, want vpce-0abc1234", p.DenyVpceID)
	}
}

func TestBuilder_BucketPolicy_ExplicitDeny(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":["s3:DeleteObject"],"Resource":"*"}]}`

	config := build(t,
		bucket("my_bucket", "prod"),
		func() (string, *resolver.ResolvedResource) {
			return "aws_s3_bucket_policy.my_bucket", &resolver.ResolvedResource{
				Type: "aws_s3_bucket_policy",
				Name: "my_bucket_policy",
				Attributes: map[string]interface{}{
					"bucket": "aws_s3_bucket.my_bucket.id",
					"policy": policyJSON,
				},
				References: []string{"aws_s3_bucket.my_bucket"},
			}
		},
	)

	p := config.BucketPolicies[0]
	if !p.DenyAnyPrincipal {
		t.Error("DenyAnyPrincipal should be true for Principal:*")
	}
	found := false
	for _, a := range p.DenyActions {
		if a == "s3:DeleteObject" {
			found = true
		}
	}
	if !found {
		t.Errorf("DenyActions should contain s3:DeleteObject, got %v", p.DenyActions)
	}
}

func TestBuilder_BucketPolicy_ABACFlag(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:role/app"},"Action":"s3:GetObject","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/environment":"prod"}}}]}`

	config := build(t,
		bucket("my_bucket", "prod"),
		func() (string, *resolver.ResolvedResource) {
			return "aws_s3_bucket_policy.my_bucket", &resolver.ResolvedResource{
				Type: "aws_s3_bucket_policy",
				Name: "my_bucket_policy",
				Attributes: map[string]interface{}{
					"bucket": "aws_s3_bucket.my_bucket.id",
					"policy": policyJSON,
				},
				References: []string{"aws_s3_bucket.my_bucket"},
			}
		},
	)

	p := config.BucketPolicies[0]
	if !p.HasABAC {
		t.Error("HasABAC should be true when PrincipalTag condition is present")
	}
}

func TestBuilder_BucketPolicy_MultiStatement_NotFlattened(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"aws:sourceVpce":"vpce-abc"}}},{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:role/app"},"Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}`

	config := build(t,
		bucket("my_bucket", "prod"),
		func() (string, *resolver.ResolvedResource) {
			return "aws_s3_bucket_policy.my_bucket", &resolver.ResolvedResource{
				Type: "aws_s3_bucket_policy",
				Name: "my_bucket_policy",
				Attributes: map[string]interface{}{
					"bucket": "aws_s3_bucket.my_bucket.id",
					"policy": policyJSON,
				},
				References: []string{"aws_s3_bucket.my_bucket"},
			}
		},
	)

	if len(config.BucketPolicies) < 2 {
		t.Fatalf("expected at least 2 bucket policy entries (one per statement), got %d", len(config.BucketPolicies))
	}

	hasVPCE := false
	hasAllow := false
	for _, p := range config.BucketPolicies {
		if p.DenyVpceID != "" {
			hasVPCE = true
		}
		if len(p.AllowActions) > 0 {
			hasAllow = true
		}
	}
	if !hasVPCE {
		t.Error("VPCE deny statement should produce a policy entry with DenyVpceID")
	}
	if !hasAllow {
		t.Error("Allow statement should produce a policy entry with AllowActions")
	}
}

func TestBuilder_OrgPolicy_SCP(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}`

	config := build(t,
		func() (string, *resolver.ResolvedResource) {
			return "aws_organizations_policy.scp", &resolver.ResolvedResource{
				Type: "aws_organizations_policy",
				Name: "my_scp",
				Attributes: map[string]interface{}{
					"name":    "my-scp",
					"type":    "SERVICE_CONTROL_POLICY",
					"content": policyJSON,
				},
			}
		},
	)

	scps := config.SCPs()
	if len(scps) != 1 {
		t.Fatalf("expected 1 SCP, got %d", len(scps))
	}
	if len(scps[0].AllowActions) == 0 {
		t.Error("SCP AllowActions should be populated")
	}
}

func TestBuilder_OrgPolicy_RCP(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:DeleteObject"],"Resource":"*"}]}`

	config := build(t,
		func() (string, *resolver.ResolvedResource) {
			return "aws_organizations_policy.rcp", &resolver.ResolvedResource{
				Type: "aws_organizations_policy",
				Name: "my_rcp",
				Attributes: map[string]interface{}{
					"name":    "my-rcp",
					"type":    "RESOURCE_CONTROL_POLICY",
					"content": policyJSON,
				},
			}
		},
	)

	rcps := config.RCPs()
	if len(rcps) != 1 {
		t.Fatalf("expected 1 RCP, got %d", len(rcps))
	}
	if len(rcps[0].DenyActions) == 0 {
		t.Error("RCP DenyActions should be populated")
	}
}

func TestBuilder_InlineRolePolicy_PropagatesActions(t *testing.T) {
	policyJSON := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":"*"}]}`

	config := build(t,
		role("app_role", "app-role", "prod"),
		func() (string, *resolver.ResolvedResource) {
			return "aws_iam_role_policy.inline", &resolver.ResolvedResource{
				Type: "aws_iam_role_policy",
				Name: "inline_policy",
				Attributes: map[string]interface{}{
					"role":   "aws_iam_role.app_role.name",
					"policy": policyJSON,
				},
				References: []string{"aws_iam_role.app_role"},
			}
		},
	)

	r := config.GetRoleByTFName("app_role")
	if r == nil {
		t.Fatal("role not found")
	}
	if !r.HasRolePolicy {
		t.Error("HasRolePolicy should be true when inline policy is attached")
	}
	found := false
	for _, a := range r.RolePolicyActions {
		if a == "s3:PutObject" {
			found = true
		}
	}
	if !found {
		t.Errorf("s3:PutObject should be in RolePolicyActions from inline policy, got %v", r.RolePolicyActions)
	}
}

func TestBuilder_MultipleRolesAndBuckets_Independent(t *testing.T) {
	config := build(t,
		bucket("bucket_a", "prod"),
		bucket("bucket_b", "dev"),
		role("role_a", "role-a", "prod"),
		role("role_b", "role-b", "dev"),
	)

	if len(config.Buckets) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(config.Buckets))
	}
	if len(config.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(config.Roles))
	}

	ba := config.GetBucketByTFName("bucket_a")
	bb := config.GetBucketByTFName("bucket_b")
	if ba == nil || bb == nil {
		t.Fatal("expected both buckets to be found")
	}
	if ba.EnvTag != "prod" {
		t.Errorf("bucket_a EnvTag = %q, want prod", ba.EnvTag)
	}
	if bb.EnvTag != "dev" {
		t.Errorf("bucket_b EnvTag = %q, want dev", bb.EnvTag)
	}
}

func TestBuilder_EmptyResources_ReturnsEmptyConfig(t *testing.T) {
	config := build(t)

	if len(config.Buckets) != 0 {
		t.Errorf("expected 0 buckets, got %d", len(config.Buckets))
	}
	if len(config.Roles) != 0 {
		t.Errorf("expected 0 roles, got %d", len(config.Roles))
	}
	if len(config.BucketPolicies) != 0 {
		t.Errorf("expected 0 bucket policies, got %d", len(config.BucketPolicies))
	}
}
