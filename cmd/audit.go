package cmd

import (
	"fmt"

	"github.com/moveeeax/k8s-netpol-coverage/internal/audit"
	"github.com/moveeeax/k8s-netpol-coverage/internal/report"
	"github.com/spf13/cobra"
)

func newAuditCmd() *cobra.Command {
	var (
		output string
		failOn string
	)
	cmd := &cobra.Command{
		Use:   "audit <path>",
		Short: "Audit the manifests under <path> for NetworkPolicy coverage",
		Long: "Audit reads every Kubernetes YAML file under <path> and reports " +
			"workloads no NetworkPolicy selects, namespaces with no default-deny, " +
			"and policies whose selectors match nothing.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAudit(cmd, args[0], output, failOn)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table, json, or sarif")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero when a finding is at least this severity: low, medium, or high")
	return cmd
}

func runAudit(cmd *cobra.Command, path, output, failOn string) error {
	var threshold audit.Severity
	if failOn != "" {
		parsed, err := audit.ParseSeverity(failOn)
		if err != nil {
			return err
		}
		threshold = parsed
	}

	manifests, err := audit.Load(path)
	if err != nil {
		return err
	}
	findings := audit.Analyze(manifests)

	rep := report.Report{
		Version:   version,
		Workloads: len(manifests.Workloads),
		Policies:  len(manifests.Policies),
		Findings:  findings,
	}
	if err := report.Write(cmd.OutOrStdout(), rep, output); err != nil {
		return err
	}

	if failOn != "" && maxSeverity(findings) >= threshold.Rank() {
		return fmt.Errorf("%w: found a %s or higher severity finding", errGate, failOn)
	}
	return nil
}

func maxSeverity(findings []audit.Finding) int {
	max := 0
	for _, f := range findings {
		if r := f.Severity.Rank(); r > max {
			max = r
		}
	}
	return max
}
