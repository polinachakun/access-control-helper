package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "overwrite golden files with actual output")

var scenarios = []struct {
	name   string
	tf     string
	golden string
}{
	{"scenario1", "testdata/scenario1.tf", "testdata/golden/scenario1.golden"},
	{"scenario2", "testdata/scenario2.tf", "testdata/golden/scenario2.golden"},
	{"scenario3", "testdata/scenario3.tf", "testdata/golden/scenario3.golden"},
	{"test", "testdata/test.tf", "testdata/golden/test.golden"},
}

func TestScenarios(t *testing.T) {
	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			alsPath := filepath.Join(t.TempDir(), sc.name+".als")

			var buf strings.Builder
			if err := run(sc.tf, alsPath, &buf); err != nil {
				t.Fatalf("pipeline error: %v", err)
			}
			got := buf.String()

			if *update {
				if err := os.MkdirAll(filepath.Dir(sc.golden), 0755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(sc.golden, []byte(got), 0644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				t.Logf("updated %s", sc.golden)
				return
			}

			wantBytes, err := os.ReadFile(sc.golden)
			if err != nil {
				t.Fatalf("golden file missing — run: go test -run TestScenarios -update\nerror: %v", err)
			}
			want := string(wantBytes)

			if got != want {
				t.Errorf("output mismatch for %s\n\n--- want ---\n%s\n--- got ---\n%s",
					sc.name, want, got)
			}
		})
	}
}
