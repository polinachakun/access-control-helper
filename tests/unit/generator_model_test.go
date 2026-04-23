package unit_test

import (
	"strings"
	"testing"

	"access-control-helper/internal/generator"
)

func TestExpandAnalyzableActions_Wildcard(t *testing.T) {
	got := generator.ExpandAnalyzableActions([]string{"s3:*"})
	want := generator.SupportedActionsByService["s3"]
	if len(got) != len(want) {
		t.Fatalf("s3:* expanded to %d actions, want %d: %v", len(got), len(want), got)
	}
}

func TestExpandAnalyzableActions_Concrete(t *testing.T) {
	got := generator.ExpandAnalyzableActions([]string{"s3:GetObject", "s3:PutObject"})
	if len(got) != 2 {
		t.Fatalf("expected 2 concrete actions, got %d: %v", len(got), got)
	}
	if got[0] != "s3:GetObject" || got[1] != "s3:PutObject" {
		t.Errorf("got %v, want [s3:GetObject s3:PutObject]", got)
	}
}

func TestExpandAnalyzableActions_Mixed(t *testing.T) {
	got := generator.ExpandAnalyzableActions([]string{"s3:*", "s3:GetObject"})
	supported := generator.SupportedActionsByService["s3"]
	if len(got) != len(supported) {
		t.Fatalf("mixed expansion: expected %d (no dup), got %d: %v", len(supported), len(got), got)
	}
}

func TestExpandAnalyzableActions_Deduplication(t *testing.T) {
	got := generator.ExpandAnalyzableActions([]string{"s3:GetObject", "s3:GetObject"})
	if len(got) != 1 {
		t.Fatalf("expected deduplication to yield 1 action, got %d: %v", len(got), got)
	}
}

func TestExpandAnalyzableActions_SkipsEmptyAndBareWildcard(t *testing.T) {
	got := generator.ExpandAnalyzableActions([]string{"", "*", "  "})
	if len(got) != 0 {
		t.Errorf("expected empty result for bare wildcards, got %v", got)
	}
}

func TestExpandAnalyzableActions_Empty(t *testing.T) {
	got := generator.ExpandAnalyzableActions(nil)
	if len(got) != 0 {
		t.Errorf("expected empty result for nil input, got %v", got)
	}
}

func TestHumanAction(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"S3_GetObject", "s3:GetObject"},
		{"S3_PutObject", "s3:PutObject"},
		{"S3_ListBucket", "s3:ListBucket"},
		{"S3_DeleteObject", "s3:DeleteObject"},
		{"noUnderscore", "noUnderscore"},
	}
	for _, tc := range cases {
		got := generator.HumanAction(tc.input)
		if got != tc.want {
			t.Errorf("HumanAction(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestAlloyID_HyphensToUnderscores(t *testing.T) {
	got := generator.AlloyID("my-bucket")
	if got != "my_bucket" {
		t.Errorf("AlloyID(my-bucket) = %q, want my_bucket", got)
	}
}

func TestAlloyID_NumericPrefix(t *testing.T) {
	got := generator.AlloyID("123bucket")
	if !strings.HasPrefix(got, "r_") {
		t.Errorf("AlloyID(123bucket) = %q, should start with r_", got)
	}
}

func TestAlloyID_StripsInvalidChars(t *testing.T) {
	got := generator.AlloyID("my.bucket@name")
	for _, c := range got {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			t.Errorf("AlloyID produced invalid char %q in %q", c, got)
		}
	}
}

func TestAlloyID_ValidName(t *testing.T) {
	got := generator.AlloyID("my_bucket")
	if got != "my_bucket" {
		t.Errorf("AlloyID(my_bucket) = %q, want my_bucket", got)
	}
}

func TestTagToAlloyID(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"prod", "TAG_PROD"},
		{"PROD", "TAG_PROD"},
		{"my-env", "TAG_MY_ENV"},
		{"staging", "TAG_STAGING"},
	}
	for _, tc := range cases {
		got := generator.TagToAlloyID(tc.input)
		if got != tc.want {
			t.Errorf("TagToAlloyID(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestActionToAlloyID(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"s3:GetObject", "S3_GetObject"},
		{"s3:PutObject", "S3_PutObject"},
		{"s3:ListBucket", "S3_ListBucket"},
		{"s3:DeleteObject", "S3_DeleteObject"},
		{"s3:*", "S3_All"},
	}
	for _, tc := range cases {
		got := generator.ActionToAlloyID(tc.input)
		if got != tc.want {
			t.Errorf("ActionToAlloyID(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestVpceToAlloyID(t *testing.T) {
	got := generator.VpceToAlloyID("vpce-0a1b2c3d")
	want := "VPCE_0A1B2C3D"
	if got != want {
		t.Errorf("VpceToAlloyID(vpce-0a1b2c3d) = %q, want %q", got, want)
	}
}

func TestFormatAlloySet_Empty(t *testing.T) {
	got := generator.FormatAlloySet(nil)
	if got != "none" {
		t.Errorf("FormatAlloySet(nil) = %q, want none", got)
	}
}

func TestFormatAlloySet_Single(t *testing.T) {
	got := generator.FormatAlloySet([]string{"S3_GetObject"})
	if got != "S3_GetObject" {
		t.Errorf("FormatAlloySet single = %q, want S3_GetObject", got)
	}
}

func TestFormatAlloySet_Multiple(t *testing.T) {
	got := generator.FormatAlloySet([]string{"S3_GetObject", "S3_PutObject"})
	if got != "S3_GetObject + S3_PutObject" {
		t.Errorf("FormatAlloySet multiple = %q, want S3_GetObject + S3_PutObject", got)
	}
}

func TestBoolToAlloy(t *testing.T) {
	if generator.BoolToAlloy(true) != "True" {
		t.Error("BoolToAlloy(true) should be True")
	}
	if generator.BoolToAlloy(false) != "False" {
		t.Error("BoolToAlloy(false) should be False")
	}
}

func TestNormalizeActions_DeduplicatesAndConverts(t *testing.T) {
	got := generator.NormalizeActions([]string{"s3:GetObject", "s3:GetObject", "s3:PutObject"})
	if len(got) != 2 {
		t.Fatalf("expected 2 unique actions, got %d: %v", len(got), got)
	}
}

func TestNormalizeActions_SkipsBareWildcard(t *testing.T) {
	got := generator.NormalizeActions([]string{"*", "s3:GetObject"})
	if len(got) != 1 {
		t.Fatalf("expected 1 (bare * skipped), got %d: %v", len(got), got)
	}
}
