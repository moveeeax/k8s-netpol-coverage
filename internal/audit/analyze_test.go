package audit

import (
	"sort"
	"testing"
)

func mustLoad(t *testing.T, dir string) *Manifests {
	t.Helper()
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(%s): %v", dir, err)
	}
	return m
}

func ruleIDs(fs []Finding) []string {
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.RuleID
	}
	sort.Strings(ids)
	return ids
}

func TestUncoveredWorkload(t *testing.T) {
	m := mustLoad(t, "../../testdata/uncovered")
	got := ruleIDs(Analyze(m))
	want := []string{"no-default-deny-ingress", "uncovered-egress", "uncovered-ingress"}
	if !equal(got, want) {
		t.Errorf("rules = %v, want %v", got, want)
	}
}

func TestFullyCoveredHasNoFindings(t *testing.T) {
	m := mustLoad(t, "../../testdata/covered")
	if f := Analyze(m); len(f) != 0 {
		t.Errorf("expected zero findings, got %d: %v", len(f), ruleIDs(f))
	}
}

func TestDanglingSelector(t *testing.T) {
	m := mustLoad(t, "../../testdata/dangling")
	got := ruleIDs(Analyze(m))
	want := []string{"dangling-selector"}
	if !equal(got, want) {
		t.Errorf("rules = %v, want %v", got, want)
	}
	f := Analyze(m)[0]
	if f.Severity != SevLow || f.Name != "allow-worker" {
		t.Errorf("unexpected dangling finding: %+v", f)
	}
}

func TestMissingDefaultDeny(t *testing.T) {
	m := mustLoad(t, "../../testdata/no-default-deny")
	got := ruleIDs(Analyze(m))
	want := []string{"no-default-deny-ingress"}
	if !equal(got, want) {
		t.Errorf("rules = %v, want %v", got, want)
	}
}

func TestSeverityOrderingAndFailOn(t *testing.T) {
	m := mustLoad(t, "../../testdata/uncovered")
	findings := Analyze(m)
	if findings[0].Severity != SevHigh {
		t.Errorf("most-severe finding should sort first, got %s", findings[0].Severity)
	}
	high, _ := ParseSeverity("high")
	max := 0
	for _, f := range findings {
		if r := f.Severity.Rank(); r > max {
			max = r
		}
	}
	if max < high.Rank() {
		t.Error("uncovered fixture should contain a high finding to trip --fail-on high")
	}
}

func TestParseSeverityRejectsGarbage(t *testing.T) {
	if _, err := ParseSeverity("critical"); err == nil {
		t.Error("expected error for unsupported severity")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
