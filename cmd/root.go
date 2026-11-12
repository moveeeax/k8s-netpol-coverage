// Package cmd wires the cobra command tree for k8s-netpol-coverage.
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is the tool version reported by --version and in JSON/SARIF output.
const version = "0.3.0"

// errGate signals that findings met or exceeded the --fail-on threshold. It is
// separate from real runtime errors so we can exit non-zero without noise.
var errGate = errors.New("coverage gate failed")

// errDenied signals that trace found the flow denied. Like errGate it maps to
// its own exit code and prints nothing extra.
var errDenied = errors.New("flow denied")

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "k8s-netpol-coverage",
		Short:         "Audit Kubernetes manifests for NetworkPolicy coverage gaps and trace flows",
		Version:       version,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(newAuditCmd(), newTraceCmd())
	return root
}

// Execute runs the CLI and sets the process exit code:
//
//	0  clean (no error, gate not tripped, traced flow allowed)
//	1  runtime error
//	2  trace: the flow is denied
//	3  findings met the --fail-on threshold
func Execute() {
	err := newRootCmd().Execute()
	if err == nil {
		return
	}
	if errors.Is(err, errGate) {
		os.Exit(3)
	}
	if errors.Is(err, errDenied) {
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
