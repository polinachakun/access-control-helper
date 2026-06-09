package unit_test

import (
	"testing"
)

func TestManagedPolicy_AdministratorAccess(t *testing.T) {
	hcl := `
resource "aws_iam_role" "deployment" {
  name               = "deployment-role"
  assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"}}]}"
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.deployment.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "my-artifacts"
}
`
	config, warnings := parseTFString(t, hcl)

	for _, w := range warnings {
		t.Logf("warning: %s", w)
	}

	role := config.GetRoleByTFName("deployment")
	if role == nil {
		t.Fatal("role 'deployment' not found")
	}
	if !role.HasRolePolicy {
		t.Error("HasRolePolicy should be true")
	}

	actions := make(map[string]bool)
	for _, a := range role.RolePolicyActions {
		actions[a] = true
	}
	for _, want := range []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"} {
		if !actions[want] {
			t.Errorf("AdministratorAccess: %s not in RolePolicyActions %v", want, role.RolePolicyActions)
		}
	}

	perBucket := role.IdentityAllowActionsPerBucket
	if len(perBucket) == 0 {
		t.Error("IdentityAllowActionsPerBucket should not be empty for AdministratorAccess")
	}
	if _, ok := perBucket["*"]; !ok {
		t.Errorf("expected wildcard key '*' in IdentityAllowActionsPerBucket, got %v", perBucket)
	}
}

func TestManagedPolicy_S3ReadOnly(t *testing.T) {
	hcl := `
resource "aws_iam_role" "reader" {
  name               = "reader-role"
  assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"}}]}"
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.reader.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_s3_bucket" "data" {
  bucket = "my-data"
}
`
	config, _ := parseTFString(t, hcl)

	role := config.GetRoleByTFName("reader")
	if role == nil {
		t.Fatal("role 'reader' not found")
	}

	actions := make(map[string]bool)
	for _, a := range role.RolePolicyActions {
		actions[a] = true
	}
	if !actions["s3:GetObject"] {
		t.Error("AmazonS3ReadOnlyAccess: s3:GetObject should be allowed")
	}
	if !actions["s3:ListBucket"] {
		t.Error("AmazonS3ReadOnlyAccess: s3:ListBucket should be allowed")
	}
	if actions["s3:PutObject"] {
		t.Error("AmazonS3ReadOnlyAccess: s3:PutObject should NOT be allowed")
	}
	if actions["s3:DeleteObject"] {
		t.Error("AmazonS3ReadOnlyAccess: s3:DeleteObject should NOT be allowed")
	}
}

func TestManagedPolicy_Unknown(t *testing.T) {
	hcl := `
resource "aws_iam_role" "svc" {
  name               = "svc-role"
  assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"}}]}"
}

resource "aws_iam_role_policy_attachment" "custom" {
  role       = aws_iam_role.svc.name
  policy_arn = "arn:aws:iam::123456789012:policy/MyCustomPolicy"
}

resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
}
`
	config, _ := parseTFString(t, hcl)

	role := config.GetRoleByTFName("svc")
	if role == nil {
		t.Fatal("role 'svc' not found")
	}
	// Unknown custom policy — HasRolePolicy still true, but no actions resolved.
	if !role.HasRolePolicy {
		t.Error("HasRolePolicy should be true even for unknown managed policy")
	}
	if len(role.RolePolicyActions) != 0 {
		t.Errorf("custom policy should produce no resolved actions, got %v", role.RolePolicyActions)
	}
}
