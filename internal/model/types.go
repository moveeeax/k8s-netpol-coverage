// Package model holds the minimal subset of the Kubernetes API this tool needs.
// Only the fields relevant to NetworkPolicy coverage are decoded; everything
// else in a manifest is ignored. Keeping our own structs (instead of importing
// k8s.io/api) keeps the module tiny and the build fully offline.
package model

import "encoding/json"

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

// ContainerPort is one spec.containers[].ports entry of a workload's pod
// template. Only the fields needed to resolve named ports are kept.
type ContainerPort struct {
	Name          string `json:"name"`
	ContainerPort int32  `json:"containerPort"`
	Protocol      string `json:"protocol"`
}

// Workload is a normalized view of a pod-producing object.
type Workload struct {
	Kind      string
	Name      string
	Namespace string
	PodLabels map[string]string
	Ports     []ContainerPort
	File      string
}

// IntOrString mirrors intstr.IntOrString: a NetworkPolicy port is either a
// number or the name of a container port.
type IntOrString struct {
	IsString bool
	IntVal   int32
	StrVal   string
}

// UnmarshalJSON accepts both a JSON number and a JSON string.
func (v *IntOrString) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		v.IsString = true
		return json.Unmarshal(b, &v.StrVal)
	}
	return json.Unmarshal(b, &v.IntVal)
}

// IPBlock mirrors networking/v1 IPBlock.
type IPBlock struct {
	CIDR   string   `json:"cidr"`
	Except []string `json:"except"`
}

// PolicyPeer is one from/to entry of a NetworkPolicy rule. A nil selector
// means the field was absent, which Kubernetes treats differently from {}.
type PolicyPeer struct {
	PodSelector       *LabelSelector `json:"podSelector"`
	NamespaceSelector *LabelSelector `json:"namespaceSelector"`
	IPBlock           *IPBlock       `json:"ipBlock"`
}

// PolicyPort is one ports entry of a NetworkPolicy rule.
type PolicyPort struct {
	Protocol string       `json:"protocol"`
	Port     *IntOrString `json:"port"`
	EndPort  *int32       `json:"endPort"`
}

// PolicyRule is one ingress or egress rule. Peers holds "from" for ingress
// and "to" for egress; an empty list matches every peer, and an empty Ports
// list matches every port.
type PolicyRule struct {
	Peers []PolicyPeer
	Ports []PolicyPort
}

// NetworkPolicy is the subset of networking.k8s.io/v1 NetworkPolicy we audit.
type NetworkPolicy struct {
	Name        string
	Namespace   string
	PodSelector LabelSelector
	PolicyTypes []string
	HasIngress  bool
	HasEgress   bool
	Ingress     []PolicyRule
	Egress      []PolicyRule
	File        string
}
