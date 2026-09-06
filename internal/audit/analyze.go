package audit

import (
	"fmt"
	"sort"

	"github.com/moveeeax/k8s-netpol-coverage/internal/model"
)

// Severity ranks a finding. Order matters for --fail-on gating.
type Severity string

const (
	SevLow    Severity = "low"
	SevMedium Severity = "medium"
	SevHigh   Severity = "high"
)

var sevRank = map[Severity]int{SevLow: 1, SevMedium: 2, SevHigh: 3}

// Rank returns the numeric weight of a severity (higher is worse).
func (s Severity) Rank() int { return sevRank[s] }

// ParseSeverity validates a --fail-on value.
func ParseSeverity(s string) (Severity, error) {
	switch Severity(s) {
	case SevLow, SevMedium, SevHigh:
		return Severity(s), nil
	default:
		return "", fmt.Errorf("invalid severity %q (want low, medium, or high)", s)
	}
}

// Finding is one coverage gap discovered in the manifests.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Severity  Severity `json:"severity"`
	Namespace string   `json:"namespace"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Message   string   `json:"message"`
	File      string   `json:"file"`
}

// Analyze inspects the manifests and returns every coverage finding, sorted
// most-severe first for stable output.
func Analyze(m *Manifests) []Finding {
	var findings []Finding
	findings = append(findings, uncoveredWorkloads(m)...)
	findings = append(findings, missingDefaultDeny(m)...)
	findings = append(findings, danglingPolicies(m)...)
	sort.SliceStable(findings, func(i, j int) bool { return findLess(findings[i], findings[j]) })
	return findings
}

func findLess(a, b Finding) bool {
	if a.Severity.Rank() != b.Severity.Rank() {
		return a.Severity.Rank() > b.Severity.Rank()
	}
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.RuleID < b.RuleID
}

// selects reports whether a policy applies to a workload for a given direction.
func selects(p model.NetworkPolicy, w model.Workload, direction string) bool {
	if p.Namespace != w.Namespace {
		return false
	}
	if !hasType(p.PolicyTypes, direction) {
		return false
	}
	return p.PodSelector.Matches(w.PodLabels)
}

func hasType(types []string, want string) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

func uncoveredWorkloads(m *Manifests) []Finding {
	var out []Finding
	for _, w := range m.Workloads {
		coveredIn, coveredEg := false, false
		for _, p := range m.Policies {
			if selects(p, w, "Ingress") {
				coveredIn = true
			}
			if selects(p, w, "Egress") {
				coveredEg = true
			}
		}
		if !coveredIn {
			out = append(out, Finding{
				RuleID:    "uncovered-ingress",
				Severity:  SevHigh,
				Namespace: w.Namespace,
				Kind:      w.Kind,
				Name:      w.Name,
				File:      w.File,
				Message: fmt.Sprintf("%s/%s has no NetworkPolicy restricting ingress; it accepts traffic from anywhere in the cluster",
					w.Kind, w.Name),
			})
		}
		if !coveredEg {
			out = append(out, Finding{
				RuleID:    "uncovered-egress",
				Severity:  SevMedium,
				Namespace: w.Namespace,
				Kind:      w.Kind,
				Name:      w.Name,
				File:      w.File,
				Message: fmt.Sprintf("%s/%s has no NetworkPolicy restricting egress; it may reach anywhere in the cluster",
					w.Kind, w.Name),
			})
		}
	}
	return out
}

// missingDefaultDeny flags any namespace that owns a workload but has no
// default-deny ingress policy (an empty podSelector with the Ingress type and
// no ingress rules).
func missingDefaultDeny(m *Manifests) []Finding {
	nsWithWorkloads := map[string]bool{}
	for _, w := range m.Workloads {
		nsWithWorkloads[w.Namespace] = true
	}
	nsHasDefaultDeny := map[string]bool{}
	for _, p := range m.Policies {
		if p.PodSelector.IsEmpty() && hasType(p.PolicyTypes, "Ingress") && !p.HasIngress {
			nsHasDefaultDeny[p.Namespace] = true
		}
	}
	var namespaces []string
	for ns := range nsWithWorkloads {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	var out []Finding
	for _, ns := range namespaces {
		if nsHasDefaultDeny[ns] {
			continue
		}
		out = append(out, Finding{
			RuleID:    "no-default-deny-ingress",
			Severity:  SevMedium,
			Namespace: ns,
			Kind:      "Namespace",
			Name:      ns,
			Message:   fmt.Sprintf("namespace %q has no default-deny ingress policy; new workloads are open by default", ns),
		})
	}
	return out
}

// danglingPolicies flags policies whose non-empty selector matches no workload
// in their namespace, so they silently protect nothing.
func danglingPolicies(m *Manifests) []Finding {
	var out []Finding
	for _, p := range m.Policies {
		if p.PodSelector.IsEmpty() {
			continue // empty selector applies to the whole namespace, never dangling
		}
		matched := false
		for _, w := range m.Workloads {
			if w.Namespace == p.Namespace && p.PodSelector.Matches(w.PodLabels) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, Finding{
				RuleID:    "dangling-selector",
				Severity:  SevLow,
				Namespace: p.Namespace,
				Kind:      "NetworkPolicy",
				Name:      p.Name,
				File:      p.File,
				Message:   fmt.Sprintf("NetworkPolicy %q selects no workload in namespace %q; its selector is dead", p.Name, p.Namespace),
			})
		}
	}
	return out
}
