// Package cmd wires the cobra command tree for k8s-netpol-coverage.
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is the tool version reported by --version and in JSON/SARIF output.
const version = "0.2.0"

// errGate signals that findings met or exceeded the --fail-on threshold. It is
// separate from real runtime errors so we can exit non-zero without noise.
var errGate = errors.New("coverage gate failed")

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "k8s-netpol-coverage",
		Short:         "Audit Kubernetes manifests for NetworkPolicy coverage gaps",
		Version:       version,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.AddCommand(newAuditCmd())
	return root
}

// Execute runs the CLI and sets the process exit code:
//
//	0  clean (no error, gate not tripped)
//	1  runtime error
//	3  findings met the --fail-on threshold
func Execute() {
	err := newRootCmd().Execute()
	if err == nil {
		return
	}
	if errors.Is(err, errGate) {
		os.Exit(3)
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
