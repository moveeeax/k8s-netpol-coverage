package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moveeeax/k8s-netpol-coverage/internal/audit"
)

func sample() Report {
	return Report{
		Version:   "0.1.0",
		Workloads: 2,
		Policies:  1,
		Findings: []audit.Finding{
			{RuleID: "uncovered-ingress", Severity: audit.SevHigh, Namespace: "shop",
				Kind: "Deployment", Name: "web", Message: "no ingress policy", File: "web.yaml"},
			{RuleID: "dangling-selector", Severity: audit.SevLow, Namespace: "shop",
				Kind: "NetworkPolicy", Name: "stale", Message: "selects nothing", File: "np.yaml"},
		},
	}
}

func TestJSONIsValidAndCounts(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sample(), "json"); err != nil {
		t.Fatal(err)
	}
	var out jsonReport
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("json output is not valid: %v", err)
	}
	if out.Summary.Findings != 2 || out.Summary.High != 1 || out.Summary.Low != 1 {
		t.Errorf("bad summary: %+v", out.Summary)
	}
	if out.Tool != ToolName {
		t.Errorf("tool = %q", out.Tool)
	}
}

func TestSARIFIsValid(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sample(), "sarif"); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("sarif output is not valid json: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("unexpected sarif shape: %+v", log)
	}
	if len(log.Runs[0].Results) != 2 {
		t.Errorf("want 2 results, got %d", len(log.Runs[0].Results))
	}
	if log.Runs[0].Results[0].Level != "error" {
		t.Errorf("high severity should map to error, got %q", log.Runs[0].Results[0].Level)
	}
}

func TestTableCleanWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, Report{Version: "0.1.0"}, "table"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No coverage gaps") {
		t.Errorf("empty table should say so, got %q", buf.String())
	}
}

func TestUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, sample(), "xml"); err == nil {
		t.Error("expected error for unknown format")
	}
}
