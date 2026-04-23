package unit_test

import (
	"strings"
	"testing"

	"access-control-helper/internal/generator"
)

func TestBuildTripleKeys_SingleTriple(t *testing.T) {
	keys := generator.BuildTripleKeys(
		[]string{"app_role"},
		[]string{"my_bucket"},
		[]string{"S3_GetObject"},
	)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	k := keys[0]
	if k.Role != "app_role" {
		t.Errorf("Role = %q, want app_role", k.Role)
	}
	if k.Bucket != "my_bucket" {
		t.Errorf("Bucket = %q, want my_bucket", k.Bucket)
	}
	if k.Action != "S3_GetObject" {
		t.Errorf("Action = %q, want S3_GetObject", k.Action)
	}
}

func TestBuildTripleKeys_CartesianProduct(t *testing.T) {
	roles := []string{"r1", "r2"}
	buckets := []string{"b1", "b2"}
	actions := []string{"S3_GetObject", "S3_PutObject"}

	keys := generator.BuildTripleKeys(roles, buckets, actions)
	want := len(roles) * len(buckets) * len(actions)
	if len(keys) != want {
		t.Errorf("expected %d keys, got %d", want, len(keys))
	}
}

func TestBuildTripleKeys_Empty(t *testing.T) {
	keys := generator.BuildTripleKeys(nil, nil, nil)
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for empty input, got %d", len(keys))
	}
}

func TestBuildTripleKeys_AssertionBaseName_PascalCase(t *testing.T) {
	keys := generator.BuildTripleKeys(
		[]string{"app_role"},
		[]string{"my_bucket"},
		[]string{"S3_GetObject"},
	)
	name := keys[0].AssertionBaseName
	if name != "AppRoleCanGetObjectOnMyBucket" {
		t.Errorf("AssertionBaseName = %q, want AppRoleCanGetObjectOnMyBucket", name)
	}
}

func TestBuildTripleKeys_AssertionBaseName_MultiWordRole(t *testing.T) {
	keys := generator.BuildTripleKeys(
		[]string{"restricted_role"},
		[]string{"secure_bucket"},
		[]string{"S3_DeleteObject"},
	)
	name := keys[0].AssertionBaseName
	if name != "RestrictedRoleCanDeleteObjectOnSecureBucket" {
		t.Errorf("AssertionBaseName = %q, want RestrictedRoleCanDeleteObjectOnSecureBucket", name)
	}
}

func TestGenerateAccessAssertions_CountPerTriple(t *testing.T) {
	assertions := generator.GenerateAccessAssertions(
		[]string{"app_role"},
		[]string{"my_bucket"},
		[]string{"S3_GetObject"},
	)
	want := 8
	if len(assertions) != want {
		t.Fatalf("expected %d assertions per triple, got %d", want, len(assertions))
	}
}

func TestGenerateAccessAssertions_NamingConvention(t *testing.T) {
	assertions := generator.GenerateAccessAssertions(
		[]string{"app_role"},
		[]string{"my_bucket"},
		[]string{"S3_GetObject"},
	)

	baseName := "AppRoleCanGetObjectOnMyBucket"
	expectedNames := []string{
		baseName,
		baseName + "_L1",
		baseName + "_L2",
		baseName + "_L3",
		baseName + "_L4",
		baseName + "_L5",
		baseName + "_L6",
		baseName + "_L7",
	}

	for i, a := range assertions {
		if a.Name != expectedNames[i] {
			t.Errorf("assertion[%d].Name = %q, want %q", i, a.Name, expectedNames[i])
		}
	}
}

func TestGenerateAccessAssertions_MultipleTriples(t *testing.T) {
	assertions := generator.GenerateAccessAssertions(
		[]string{"r1", "r2"},
		[]string{"b1"},
		[]string{"S3_GetObject", "S3_PutObject"},
	)
	want := 32
	if len(assertions) != want {
		t.Errorf("expected %d assertions, got %d", want, len(assertions))
	}
}

func TestGenerateAccessAssertions_BodyContainsRoleAndBucket(t *testing.T) {
	assertions := generator.GenerateAccessAssertions(
		[]string{"app_role"},
		[]string{"my_bucket"},
		[]string{"S3_GetObject"},
	)
	combined := assertions[0]
	if !strings.Contains(combined.Body, "role_app_role") {
		t.Errorf("combined assertion body missing role ref:\n%s", combined.Body)
	}
	if !strings.Contains(combined.Body, "bucket_my_bucket") {
		t.Errorf("combined assertion body missing bucket ref:\n%s", combined.Body)
	}
}

func TestLayerPredicates_SevenLayers(t *testing.T) {
	if len(generator.LayerPredicates) != 7 {
		t.Errorf("expected 7 layer predicates, got %d", len(generator.LayerPredicates))
	}
}

func TestLayerPredicates_Suffixes(t *testing.T) {
	expected := []string{"_L1", "_L2", "_L3", "_L4", "_L5", "_L6", "_L7"}
	for i, lp := range generator.LayerPredicates {
		if lp.Suffix != expected[i] {
			t.Errorf("LayerPredicates[%d].Suffix = %q, want %q", i, lp.Suffix, expected[i])
		}
	}
}

func TestLayerPredicates_KindValues(t *testing.T) {
	grantingLayers := map[int]bool{3: true, 4: true}
	for i, lp := range generator.LayerPredicates {
		if grantingLayers[i] {
			if lp.Kind != "granting" {
				t.Errorf("LayerPredicates[%d] (L%d): Kind = %q, want granting", i, i+1, lp.Kind)
			}
		} else {
			if lp.Kind != "blocking" {
				t.Errorf("LayerPredicates[%d] (L%d): Kind = %q, want blocking", i, i+1, lp.Kind)
			}
		}
	}
}

func TestGeneratePredicates_NonEmpty(t *testing.T) {
	preds := generator.GeneratePredicates()
	if len(preds) == 0 {
		t.Error("GeneratePredicates returned empty slice")
	}
}

func TestGeneratePredicates_ContainsKeyPredicates(t *testing.T) {
	preds := generator.GeneratePredicates()
	names := make(map[string]bool, len(preds))
	for _, p := range preds {
		names[p.Name] = true
	}

	required := []string{
		"explicitDeny",
		"rcpAllows",
		"scpAllows",
		"resourcePolicyAllows",
		"identityPolicyAllows",
		"permBoundaryAllows",
		"sessionPolicyAllows",
		"accessAllowed",
	}
	for _, name := range required {
		if !names[name] {
			t.Errorf("GeneratePredicates missing predicate: %q", name)
		}
	}
}

func TestGenerateChecks_OneCheckPerAssertion(t *testing.T) {
	assertions := generator.GenerateAccessAssertions(
		[]string{"r1"},
		[]string{"b1"},
		[]string{"S3_GetObject"},
	)
	scope := "for exactly 1 S3Bucket"
	checks := generator.GenerateChecks(scope, assertions)
	if len(checks) != len(assertions) {
		t.Errorf("expected %d checks, got %d", len(assertions), len(checks))
	}
	for i, c := range checks {
		if c.AssertionName != assertions[i].Name {
			t.Errorf("check[%d].AssertionName = %q, want %q", i, c.AssertionName, assertions[i].Name)
		}
		if c.Scope != scope {
			t.Errorf("check[%d].Scope = %q, want %q", i, c.Scope, scope)
		}
	}
}

func TestPascalCase_ViaTripleKeys(t *testing.T) {
	cases := []struct {
		role   string
		bucket string
		action string
		want   string
	}{
		{"app_role", "my_bucket", "S3_GetObject", "AppRoleCanGetObjectOnMyBucket"},
		{"app_role", "my_bucket", "S3_ListBucket", "AppRoleCanListBucketOnMyBucket"},
		{"app_role", "my_bucket", "S3_DeleteObject", "AppRoleCanDeleteObjectOnMyBucket"},
		{"app_role", "my_bucket", "S3_PutObject", "AppRoleCanPutObjectOnMyBucket"},
	}
	for _, tc := range cases {
		keys := generator.BuildTripleKeys([]string{tc.role}, []string{tc.bucket}, []string{tc.action})
		if len(keys) != 1 {
			t.Fatalf("expected 1 key for %v", tc)
		}
		got := keys[0].AssertionBaseName
		if got != tc.want {
			t.Errorf("triple (%s,%s,%s): AssertionBaseName = %q, want %q",
				tc.role, tc.bucket, tc.action, got, tc.want)
		}
	}
}
