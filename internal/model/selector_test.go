package model

import "testing"

func TestEmptySelectorMatchesEverything(t *testing.T) {
	var s LabelSelector
	if !s.IsEmpty() {
		t.Fatal("zero-value selector should be empty")
	}
	if !s.Matches(map[string]string{"app": "web"}) {
		t.Error("empty selector must match any labels")
	}
	if !s.Matches(nil) {
		t.Error("empty selector must match a pod with no labels")
	}
}

func TestMatchLabels(t *testing.T) {
	s := LabelSelector{MatchLabels: map[string]string{"app": "web", "tier": "frontend"}}
	if !s.Matches(map[string]string{"app": "web", "tier": "frontend", "extra": "x"}) {
		t.Error("superset of required labels should match")
	}
	if s.Matches(map[string]string{"app": "web"}) {
		t.Error("missing a required label should not match")
	}
	if s.Matches(map[string]string{"app": "api", "tier": "frontend"}) {
		t.Error("wrong value should not match")
	}
}

func TestMatchExpressions(t *testing.T) {
	cases := []struct {
		name   string
		req    LabelSelectorRequirement
		labels map[string]string
		want   bool
	}{
		{"In hit", LabelSelectorRequirement{"env", "In", []string{"prod", "stage"}}, map[string]string{"env": "prod"}, true},
		{"In miss", LabelSelectorRequirement{"env", "In", []string{"prod"}}, map[string]string{"env": "dev"}, false},
		{"NotIn hit", LabelSelectorRequirement{"env", "NotIn", []string{"prod"}}, map[string]string{"env": "dev"}, true},
		{"NotIn absent", LabelSelectorRequirement{"env", "NotIn", []string{"prod"}}, map[string]string{}, true},
		{"Exists hit", LabelSelectorRequirement{"env", "Exists", nil}, map[string]string{"env": "x"}, true},
		{"Exists miss", LabelSelectorRequirement{"env", "Exists", nil}, map[string]string{}, false},
		{"DoesNotExist hit", LabelSelectorRequirement{"env", "DoesNotExist", nil}, map[string]string{}, true},
		{"unknown op", LabelSelectorRequirement{"env", "Bogus", nil}, map[string]string{"env": "x"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := LabelSelector{MatchExpressions: []LabelSelectorRequirement{tc.req}}
			if got := s.Matches(tc.labels); got != tc.want {
				t.Errorf("Matches() = %v, want %v", got, tc.want)
			}
		})
	}
}
