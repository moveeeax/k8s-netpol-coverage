package trace

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/moveeeax/k8s-netpol-coverage/internal/audit"
)

func load(t *testing.T) *audit.Manifests {
	t.Helper()
	m, err := audit.Load("../../testdata/trace")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return m
}

func run(t *testing.T, m *audit.Manifests, from, to string, port int32, proto string) Result {
	t.Helper()
	src, err := ResolveEndpoint(m, from)
	if err != nil {
		t.Fatalf("ResolveEndpoint(%q): %v", from, err)
	}
	dst, err := ResolveEndpoint(m, to)
	if err != nil {
		t.Fatalf("ResolveEndpoint(%q): %v", to, err)
	}
	res, err := Evaluate(m, Flow{From: src, To: dst, Port: port, Protocol: proto})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return res
}

func TestTraceDecisions(t *testing.T) {
	m := load(t)
	cases := []struct {
		name            string
		from, to        string
		port            int32
		proto           string
		allowed         bool
		egress, ingress Decision
		egressBy        string // "policy#rule" of the deciding egress rule, if any
		ingressBy       string
	}{
		{"named port on destination", "app/web", "app/StatefulSet/db", 5432, "TCP", true,
			AllowedByRule, AllowedByRule, "web-egress#0", "db-ingress#0"},
		{"wrong port on isolated pods", "app/web", "app/StatefulSet/db", 5433, "TCP", false,
			NoMatchingRule, NoMatchingRule, "", ""},
		{"protocol mismatch", "app/web", "app/StatefulSet/db", 5432, "udp", false,
			NoMatchingRule, NoMatchingRule, "", ""},
		{"namespaceSelector on Namespace labels plus endPort range", "monitoring/prometheus", "app/StatefulSet/db", 9150, "TCP", true,
			NotIsolated, AllowedByRule, "", "db-ingress#1"},
		{"endPort upper bound is inclusive", "monitoring/prometheus", "app/StatefulSet/db", 9200, "TCP", true,
			NotIsolated, AllowedByRule, "", "db-ingress#1"},
		{"outside endPort range", "monitoring/prometheus", "app/StatefulSet/db", 9201, "TCP", false,
			NotIsolated, NoMatchingRule, "", ""},
		{"ipBlock hit", "app/web", "203.0.113.10", 443, "TCP", true,
			AllowedByRule, NotApplicable, "web-egress#1", ""},
		{"ipBlock except", "app/web", "203.0.113.200", 443, "TCP", false,
			NoMatchingRule, NotApplicable, "", ""},
		{"CIDR inside ipBlock", "app/web", "203.0.113.0/26", 443, "TCP", true,
			AllowedByRule, NotApplicable, "web-egress#1", ""},
		{"CIDR overlapping except", "app/web", "203.0.113.0/24", 443, "TCP", false,
			NoMatchingRule, NotApplicable, "", ""},
		{"external source to named port", "198.51.100.7", "app/web", 8080, "TCP", true,
			NotApplicable, AllowedByRule, "", "web-ingress#0"},
		{"metadata.name label without Namespace manifest", "app/web", "jobs/batch", 22, "TCP", true,
			AllowedByRule, NotIsolated, "web-egress#2", ""},
		{"deny-all isolation", "jobs/batch", "app/Pod/db", 80, "TCP", false,
			NotIsolated, DenyAll, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := run(t, m, tc.from, tc.to, tc.port, tc.proto)
			if res.Allowed != tc.allowed {
				t.Errorf("Allowed = %v, want %v (%s | %s)", res.Allowed, tc.allowed, res.Egress.Message, res.Ingress.Message)
			}
			if res.Egress.Decision != tc.egress {
				t.Errorf("egress decision = %s, want %s: %s", res.Egress.Decision, tc.egress, res.Egress.Message)
			}
			if res.Ingress.Decision != tc.ingress {
				t.Errorf("ingress decision = %s, want %s: %s", res.Ingress.Decision, tc.ingress, res.Ingress.Message)
			}
			if got := ref(res.Egress.DecidedBy); got != tc.egressBy {
				t.Errorf("egress decided by %q, want %q", got, tc.egressBy)
			}
			if got := ref(res.Ingress.DecidedBy); got != tc.ingressBy {
				t.Errorf("ingress decided by %q, want %q", got, tc.ingressBy)
			}
		})
	}
}

func ref(r *PolicyRef) string {
	if r == nil {
		return ""
	}
	return r.Name + "#" + strconv.Itoa(*r.Rule)
}

func TestIsolatingPoliciesAreNamed(t *testing.T) {
	res := run(t, load(t), "app/web", "app/StatefulSet/db", 5433, "TCP")
	var names []string
	for _, p := range res.Ingress.Isolating {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "db-ingress,default-deny" {
		t.Errorf("isolating ingress policies = %v", names)
	}
	if !strings.Contains(res.Ingress.Message, "app/db-ingress, app/default-deny") {
		t.Errorf("message does not name the policies: %s", res.Ingress.Message)
	}
}

func TestResolveEndpointErrors(t *testing.T) {
	m := load(t)
	for _, ref := range []string{"app/db", "app/missing", "a/b/c/d", "app/Job/web"} {
		if _, err := ResolveEndpoint(m, ref); err == nil {
			t.Errorf("ResolveEndpoint(%q) succeeded, want error", ref)
		}
	}
	e, err := ResolveEndpoint(m, "app/statefulset/db")
	if err != nil || e.Workload.Kind != "StatefulSet" {
		t.Errorf("kind should match case-insensitively: %v %+v", err, e)
	}
}

func TestEvaluateRejectsBadInput(t *testing.T) {
	m := load(t)
	web, _ := ResolveEndpoint(m, "app/web")
	ext, _ := ResolveEndpoint(m, "10.0.0.1")
	bad := []Flow{
		{From: ext, To: ext, Port: 80, Protocol: "TCP"},
		{From: web, To: ext, Port: 0, Protocol: "TCP"},
		{From: web, To: ext, Port: 70000, Protocol: "TCP"},
		{From: web, To: ext, Port: 80, Protocol: "ICMP"},
	}
	for _, f := range bad {
		if _, err := Evaluate(m, f); err == nil {
			t.Errorf("Evaluate(%+v) succeeded, want error", f)
		}
	}
}

func TestWriteFormats(t *testing.T) {
	res := run(t, load(t), "jobs/batch", "app/Pod/db", 80, "TCP")
	var buf bytes.Buffer
	if err := Write(&buf, res, "table"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Verdict: DENIED") || !strings.Contains(buf.String(), "deny-all") {
		t.Errorf("table output missing verdict:\n%s", buf.String())
	}
	buf.Reset()
	if err := Write(&buf, res, "json"); err != nil {
		t.Fatal(err)
	}
	var out Result
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json output is not valid: %v", err)
	}
	if out.Allowed || out.Ingress.Decision != DenyAll || out.To != "app/Pod/db" {
		t.Errorf("bad json result: %+v", out)
	}
	if err := Write(&buf, res, "sarif"); err == nil {
		t.Error("sarif is not a trace format and should be rejected")
	}
}
