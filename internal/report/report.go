// Package report renders audit findings as a table, JSON, or SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/moveeeax/k8s-netpol-coverage/internal/audit"
)

// ToolName is the driver/tool identifier emitted in JSON and SARIF.
const ToolName = "k8s-netpol-coverage"

// Report bundles the findings with the totals needed by every format.
type Report struct {
	Version   string
	Workloads int
	Policies  int
	Findings  []audit.Finding
}

// Write renders the report to w in the given format ("table", "json", "sarif").
func Write(w io.Writer, r Report, format string) error {
	switch format {
	case "table", "":
		return writeTable(w, r)
	case "json":
		return writeJSON(w, r)
	case "sarif":
		return writeSARIF(w, r)
	default:
		return fmt.Errorf("unknown output format %q (want table, json, or sarif)", format)
	}
}

func counts(fs []audit.Finding) (high, medium, low int) {
	for _, f := range fs {
		switch f.Severity {
		case audit.SevHigh:
			high++
		case audit.SevMedium:
			medium++
		case audit.SevLow:
			low++
		}
	}
	return
}

func writeTable(w io.Writer, r Report) error {
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "No coverage gaps found across %d workload(s) and %d policy(ies).\n",
			r.Workloads, r.Policies)
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE\tNAMESPACE\tRESOURCE\tMESSAGE")
	for _, f := range r.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s/%s\t%s\n",
			strings.ToUpper(string(f.Severity)), f.RuleID, f.Namespace, f.Kind, f.Name, f.Message)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	high, medium, low := counts(r.Findings)
	fmt.Fprintf(w, "\n%d finding(s): %d high, %d medium, %d low across %d workload(s), %d policy(ies).\n",
		len(r.Findings), high, medium, low, r.Workloads, r.Policies)
	return nil
}

type jsonSummary struct {
	Workloads int `json:"workloads"`
	Policies  int `json:"policies"`
	Findings  int `json:"findings"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
}

type jsonReport struct {
	Tool     string          `json:"tool"`
	Version  string          `json:"version"`
	Summary  jsonSummary     `json:"summary"`
	Findings []audit.Finding `json:"findings"`
}

func writeJSON(w io.Writer, r Report) error {
	high, medium, low := counts(r.Findings)
	findings := r.Findings
	if findings == nil {
		findings = []audit.Finding{}
	}
	out := jsonReport{
		Tool:    ToolName,
		Version: r.Version,
		Summary: jsonSummary{
			Workloads: r.Workloads, Policies: r.Policies, Findings: len(findings),
			High: high, Medium: medium, Low: low,
		},
		Findings: findings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// --- SARIF 2.1.0 ---

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID string `json:"id"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

func sarifLevel(s audit.Severity) string {
	switch s {
	case audit.SevHigh:
		return "error"
	case audit.SevMedium:
		return "warning"
	default:
		return "note"
	}
}

func writeSARIF(w io.Writer, r Report) error {
	ruleSet := map[string]bool{}
	var results []sarifResult
	for _, f := range r.Findings {
		ruleSet[f.RuleID] = true
		res := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
		}
		if f.File != "" {
			res.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.File}},
			}}
		}
		results = append(results, res)
	}
	var ruleIDs []string
	for id := range ruleSet {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, sarifRule{ID: id})
	}
	if results == nil {
		results = []sarifResult{}
	}
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           ToolName,
				InformationURI: "https://github.com/moveeeax/k8s-netpol-coverage",
				Version:        r.Version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
