// Package model holds the minimal subset of the Kubernetes API this tool needs.
// Only the fields relevant to NetworkPolicy coverage are decoded; everything
// else in a manifest is ignored. Keeping our own structs (instead of importing
// k8s.io/api) keeps the module tiny and the build fully offline.
package model

// TypeMeta identifies the kind of a manifest document.
type TypeMeta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// ObjectMeta is the shared metadata of every object.
type ObjectMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

// LabelSelectorRequirement is one matchExpressions entry.
type LabelSelectorRequirement struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

// LabelSelector mirrors metav1.LabelSelector.
type LabelSelector struct {
	MatchLabels      map[string]string          `json:"matchLabels"`
	MatchExpressions []LabelSelectorRequirement `json:"matchExpressions"`
}

// IsEmpty reports whether the selector matches every pod (the {} selector).
func (s *LabelSelector) IsEmpty() bool {
	if s == nil {
		return true
	}
	return len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0
}

// Workload is a normalized view of a pod-producing object.
type Workload struct {
	Kind      string
	Name      string
	Namespace string
	PodLabels map[string]string
	File      string
}

// NetworkPolicy is the subset of networking.k8s.io/v1 NetworkPolicy we audit.
type NetworkPolicy struct {
	Name        string
	Namespace   string
	PodSelector LabelSelector
	PolicyTypes []string
	HasIngress  bool
	HasEgress   bool
	File        string
}
