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

func TestLoadParsesRulesPortsAndNamespaces(t *testing.T) {
	m := mustLoad(t, "../../testdata/trace")
	if got := m.NamespaceLabels["monitoring"]["team"]; got != "observability" {
		t.Errorf("namespace label = %q", got)
	}
	var found bool
	for _, p := range m.Policies {
		if p.Name != "db-ingress" {
			continue
		}
		found = true
		if len(p.Ingress) != 2 || len(p.Egress) != 0 {
			t.Fatalf("db-ingress rules: %d ingress, %d egress", len(p.Ingress), len(p.Egress))
		}
		named := p.Ingress[0].Ports[0].Port
		if named == nil || !named.IsString || named.StrVal != "pg" {
			t.Errorf("named port not decoded: %+v", named)
		}
		ranged := p.Ingress[1].Ports[0]
		if ranged.Port.IsString || ranged.Port.IntVal != 9100 || ranged.EndPort == nil || *ranged.EndPort != 9200 {
			t.Errorf("numeric port range not decoded: %+v", ranged)
		}
		peer := p.Ingress[1].Peers[0]
		if peer.NamespaceSelector == nil || peer.PodSelector == nil {
			t.Errorf("combined namespace+pod peer not decoded: %+v", peer)
		}
	}
	if !found {
		t.Fatal("db-ingress policy not loaded")
	}
	for _, w := range m.Workloads {
		if w.Kind == "StatefulSet" && w.Name == "db" {
			if len(w.Ports) != 1 || w.Ports[0].Name != "pg" || w.Ports[0].ContainerPort != 5432 {
				t.Errorf("container ports = %+v", w.Ports)
			}
		}
	}
}
