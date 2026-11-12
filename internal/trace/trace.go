// Package trace explains whether one flow between two endpoints is allowed by
// the NetworkPolicies in a manifest tree, naming the policy and rule that
// decided each direction.
//
// A flow needs two permissions: egress on the source pod and ingress on the
// destination pod. Each direction is evaluated on its own, following the
// networking.k8s.io/v1 semantics: a pod no policy selects for a direction is
// not isolated and allows everything; a selected pod allows only what at least
// one rule of one selecting policy permits. NetworkPolicy has no deny rules, so
// every denial is isolation.
package trace

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/moveeeax/k8s-netpol-coverage/internal/audit"
	"github.com/moveeeax/k8s-netpol-coverage/internal/model"
)

// namespaceNameLabel is set by the control plane on every namespace, so a
// namespaceSelector can match it even when no Namespace manifest is present.
const namespaceNameLabel = "kubernetes.io/metadata.name"

// Endpoint is one side of a flow: a workload from the manifests or an address
// range outside the cluster.
type Endpoint struct {
	Workload *model.Workload
	Prefix   netip.Prefix
}

// External reports whether the endpoint is an IP or CIDR, not a workload.
func (e Endpoint) External() bool { return e.Workload == nil }

func (e Endpoint) String() string {
	if e.External() {
		return e.Prefix.String()
	}
	return fmt.Sprintf("%s/%s/%s", e.Workload.Namespace, e.Workload.Kind, e.Workload.Name)
}

// ResolveEndpoint turns a --from/--to value into an Endpoint. Accepted forms:
// an IP address or CIDR (external), "namespace/name", "namespace/Kind/name",
// or a bare "name" in the default namespace.
func ResolveEndpoint(m *audit.Manifests, ref string) (Endpoint, error) {
	if addr, err := netip.ParseAddr(ref); err == nil {
		return Endpoint{Prefix: netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())}, nil
	}
	if p, err := netip.ParsePrefix(ref); err == nil {
		return Endpoint{Prefix: p.Masked()}, nil
	}
	var ns, kind, name string
	parts := strings.Split(ref, "/")
	switch len(parts) {
	case 1:
		ns, name = "default", parts[0]
	case 2:
		ns, name = parts[0], parts[1]
	case 3:
		ns, kind, name = parts[0], parts[1], parts[2]
	default:
		return Endpoint{}, fmt.Errorf("invalid endpoint %q (want namespace/name, namespace/Kind/name, an IP, or a CIDR)", ref)
	}
	var found []*model.Workload
	for i := range m.Workloads {
		w := &m.Workloads[i]
		if w.Namespace == ns && w.Name == name && (kind == "" || strings.EqualFold(w.Kind, kind)) {
			found = append(found, w)
		}
	}
	switch len(found) {
	case 0:
		return Endpoint{}, fmt.Errorf("endpoint %q: no workload with that name in namespace %q", ref, ns)
	case 1:
		return Endpoint{Workload: found[0]}, nil
	default:
		kinds := make([]string, len(found))
		for i, w := range found {
			kinds[i] = w.Kind
		}
		return Endpoint{}, fmt.Errorf("endpoint %q is ambiguous (%s); use namespace/Kind/name",
			ref, strings.Join(kinds, ", "))
	}
}

// Decision says why a direction was allowed or denied.
type Decision string

const (
	// NotApplicable: the endpoint is outside the cluster, so no policy applies
	// on this side of the flow.
	NotApplicable Decision = "not-applicable"
	// NotIsolated: no policy selects the pod for this direction, so Kubernetes
	// allows all traffic in that direction.
	NotIsolated Decision = "not-isolated"
	// AllowedByRule: a rule of a selecting policy permits the flow.
	AllowedByRule Decision = "allowed-by-rule"
	// DenyAll: every selecting policy has no rules for this direction, i.e.
	// the pod sits behind a deny-all policy.
	DenyAll Decision = "deny-all"
	// NoMatchingRule: the selecting policies have rules, but none matches
	// this peer, port, and protocol.
	NoMatchingRule Decision = "no-matching-rule"
)

// PolicyRef names a policy and, when relevant, one of its rules.
type PolicyRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Rule is the zero-based index into the policy's ingress or egress list.
	Rule *int   `json:"rule,omitempty"`
	File string `json:"file,omitempty"`
}

func (r PolicyRef) String() string {
	return r.Namespace + "/" + r.Name
}

// Step is the verdict for one direction of the flow.
type Step struct {
	Direction string   `json:"direction"`
	Allowed   bool     `json:"allowed"`
	Decision  Decision `json:"decision"`
	// DecidedBy is the policy and rule that allowed the flow (AllowedByRule).
	DecidedBy *PolicyRef `json:"decidedBy,omitempty"`
	// Isolating lists every policy that selects the pod for this direction.
	Isolating []PolicyRef `json:"isolatingPolicies,omitempty"`
	Message   string      `json:"message"`
}

// Result is the full verdict for a flow.
type Result struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Protocol string `json:"protocol"`
	Port     int32  `json:"port"`
	Allowed  bool   `json:"allowed"`
	Egress   Step   `json:"egress"`
	Ingress  Step   `json:"ingress"`
}

// Flow is the traffic to evaluate.
type Flow struct {
	From     Endpoint
	To       Endpoint
	Protocol string
	Port     int32
}

// NormalizeProtocol validates a --protocol value and returns it upper-cased.
func NormalizeProtocol(p string) (string, error) {
	switch up := strings.ToUpper(p); up {
	case "TCP", "UDP", "SCTP":
		return up, nil
	default:
		return "", fmt.Errorf("invalid protocol %q (want TCP, UDP, or SCTP)", p)
	}
}

// Evaluate traces the flow through the policies in m. Policies are expected in
// the stable namespace/name order Load returns, so the first allowing rule
// reported is deterministic.
func Evaluate(m *audit.Manifests, f Flow) (Result, error) {
	if f.From.External() && f.To.External() {
		return Result{}, fmt.Errorf("at least one of --from and --to must be a workload")
	}
	if f.Port < 1 || f.Port > 65535 {
		return Result{}, fmt.Errorf("invalid port %d (want 1-65535)", f.Port)
	}
	proto, err := NormalizeProtocol(f.Protocol)
	if err != nil {
		return Result{}, err
	}
	f.Protocol = proto

	res := Result{
		From:     f.From.String(),
		To:       f.To.String(),
		Protocol: f.Protocol,
		Port:     f.Port,
	}
	if f.From.External() {
		res.Egress = Step{Direction: "Egress", Allowed: true, Decision: NotApplicable,
			Message: fmt.Sprintf("source %s is outside the cluster; no egress policy applies", f.From)}
	} else {
		res.Egress = evaluate(m, f, "Egress", *f.From.Workload, f.To)
	}
	if f.To.External() {
		res.Ingress = Step{Direction: "Ingress", Allowed: true, Decision: NotApplicable,
			Message: fmt.Sprintf("destination %s is outside the cluster; no ingress policy applies", f.To)}
	} else {
		res.Ingress = evaluate(m, f, "Ingress", *f.To.Workload, f.From)
	}
	res.Allowed = res.Egress.Allowed && res.Ingress.Allowed
	return res, nil
}

// evaluate decides one direction. subject is the pod the policies must select
// (the source for egress, the destination for ingress); peer is the other end.
func evaluate(m *audit.Manifests, f Flow, direction string, subject model.Workload, peer Endpoint) Step {
	step := Step{Direction: direction}
	who := subject.Kind + "/" + subject.Name
	var decided *PolicyRef
	anyRules := false
	for _, p := range m.Policies {
		if !audit.Selects(p, subject, direction) {
			continue
		}
		step.Isolating = append(step.Isolating, PolicyRef{Namespace: p.Namespace, Name: p.Name, File: p.File})
		rules := p.Ingress
		if direction == "Egress" {
			rules = p.Egress
		}
		if len(rules) > 0 {
			anyRules = true
		}
		if decided != nil {
			continue
		}
		for i, r := range rules {
			if ruleMatches(m, p.Namespace, r, peer, f) {
				idx := i
				decided = &PolicyRef{Namespace: p.Namespace, Name: p.Name, Rule: &idx, File: p.File}
				break
			}
		}
	}

	lower := strings.ToLower(direction)
	prep := "from"
	if direction == "Egress" {
		prep = "to"
	}
	flow := fmt.Sprintf("%s/%d %s %s", f.Protocol, f.Port, prep, peer)
	switch {
	case len(step.Isolating) == 0:
		step.Allowed = true
		step.Decision = NotIsolated
		step.Message = fmt.Sprintf("no NetworkPolicy selects %s for %s, so all %s traffic is allowed", who, lower, lower)
	case decided != nil:
		step.Allowed = true
		step.Decision = AllowedByRule
		step.DecidedBy = decided
		step.Message = fmt.Sprintf("%s rule %d of NetworkPolicy %s allows %s", lower, *decided.Rule, decided, flow)
	case !anyRules:
		step.Decision = DenyAll
		step.Message = fmt.Sprintf("%s is isolated for %s by %s, which has no %s rules (deny-all); %s is dropped",
			who, lower, policyList(step.Isolating), lower, flow)
	default:
		step.Decision = NoMatchingRule
		step.Message = fmt.Sprintf("%s is isolated for %s by %s; no %s rule allows %s",
			who, lower, policyList(step.Isolating), lower, flow)
	}
	return step
}

func policyList(refs []PolicyRef) string {
	names := make([]string, len(refs))
	for i, r := range refs {
		names[i] = r.String()
	}
	return strings.Join(names, ", ")
}

func ruleMatches(m *audit.Manifests, policyNS string, r model.PolicyRule, peer Endpoint, f Flow) bool {
	// Named ports resolve against the destination pod in both directions; it
	// is nil when the flow leaves the cluster, so named ports cannot match.
	if !portsMatch(r.Ports, f.Protocol, f.Port, f.To.Workload) {
		return false
	}
	if len(r.Peers) == 0 {
		return true // no from/to: every peer, in or out of the cluster
	}
	for _, p := range r.Peers {
		if peer.External() {
			if peerMatchesPrefix(p, peer.Prefix) {
				return true
			}
		} else if peerMatchesPod(m, policyNS, p, *peer.Workload) {
			return true
		}
	}
	return false
}

// peerMatchesPod applies podSelector/namespaceSelector semantics. An ipBlock
// peer never matches a workload: pod IPs are not known from manifests, and the
// Kubernetes docs scope ipBlock to cluster-external addresses.
func peerMatchesPod(m *audit.Manifests, policyNS string, p model.PolicyPeer, w model.Workload) bool {
	if p.IPBlock != nil {
		return false
	}
	if p.PodSelector == nil && p.NamespaceSelector == nil {
		return false // an empty peer is invalid; never overstate access
	}
	if p.NamespaceSelector != nil {
		if !p.NamespaceSelector.Matches(namespaceLabels(m, w.Namespace)) {
			return false
		}
	} else if w.Namespace != policyNS {
		return false
	}
	return p.PodSelector.Matches(w.PodLabels) // nil selector: every pod
}

func namespaceLabels(m *audit.Manifests, ns string) map[string]string {
	out := map[string]string{}
	for k, v := range m.NamespaceLabels[ns] {
		out[k] = v
	}
	out[namespaceNameLabel] = ns
	return out
}

// peerMatchesPrefix reports whether an ipBlock peer covers the whole target
// range: the cidr must contain it and no except entry may overlap it. For a
// single IP that is plain membership.
func peerMatchesPrefix(p model.PolicyPeer, target netip.Prefix) bool {
	if p.IPBlock == nil {
		return false
	}
	cidr, err := netip.ParsePrefix(p.IPBlock.CIDR)
	if err != nil {
		return false
	}
	cidr = cidr.Masked()
	if cidr.Addr().Is4() != target.Addr().Is4() {
		return false
	}
	if cidr.Bits() > target.Bits() || !cidr.Contains(target.Addr()) {
		return false
	}
	for _, e := range p.IPBlock.Except {
		ex, err := netip.ParsePrefix(e)
		if err != nil {
			continue
		}
		if ex.Masked().Overlaps(target) {
			return false
		}
	}
	return true
}

// portsMatch reports whether a rule's ports list admits the flow. An empty
// list admits every port and protocol; an entry without a port admits every
// port of its protocol; protocol defaults to TCP.
func portsMatch(ports []model.PolicyPort, proto string, port int32, dst *model.Workload) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		pp := p.Protocol
		if pp == "" {
			pp = "TCP"
		}
		if !strings.EqualFold(pp, proto) {
			continue
		}
		if p.Port == nil {
			return true
		}
		if p.Port.IsString {
			if dst != nil && namedPort(*dst, p.Port.StrVal, proto, port) {
				return true
			}
			continue
		}
		lo, hi := p.Port.IntVal, p.Port.IntVal
		if p.EndPort != nil {
			hi = *p.EndPort
		}
		if port >= lo && port <= hi {
			return true
		}
	}
	return false
}

func namedPort(w model.Workload, name, proto string, port int32) bool {
	for _, cp := range w.Ports {
		cpProto := cp.Protocol
		if cpProto == "" {
			cpProto = "TCP"
		}
		if cp.Name == name && cp.ContainerPort == port && strings.EqualFold(cpProto, proto) {
			return true
		}
	}
	return false
}
