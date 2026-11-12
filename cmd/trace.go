package cmd

import (
	"fmt"

	"github.com/moveeeax/k8s-netpol-coverage/internal/audit"
	"github.com/moveeeax/k8s-netpol-coverage/internal/trace"
	"github.com/spf13/cobra"
)

func newTraceCmd() *cobra.Command {
	var (
		from, to, protocol, output string
		port                       int32
	)
	cmd := &cobra.Command{
		Use:   "trace <path> --from <endpoint> --to <endpoint> --port <n>",
		Short: "Explain whether the manifests under <path> allow one flow",
		Long: "Trace evaluates the NetworkPolicies under <path> for a single flow and names " +
			"the policy and rule that allowed or isolated each direction: egress on the " +
			"source and ingress on the destination.\n\n" +
			"An endpoint is namespace/name, namespace/Kind/name, a bare name in the " +
			"default namespace, or an IP address or CIDR outside the cluster.",
		Example: "  k8s-netpol-coverage trace ./k8s --from shop/storefront --to shop/orders-db --port 5432\n" +
			"  k8s-netpol-coverage trace ./k8s --from shop/Deployment/storefront --to 203.0.113.10 --port 443",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrace(cmd, args[0], from, to, protocol, port, output)
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "source endpoint (required)")
	cmd.Flags().StringVar(&to, "to", "", "destination endpoint (required)")
	cmd.Flags().Int32Var(&port, "port", 0, "destination port number (required)")
	cmd.Flags().StringVar(&protocol, "protocol", "TCP", "protocol: TCP, UDP, or SCTP")
	cmd.Flags().StringVarP(&output, "output", "o", "table", "output format: table or json")
	for _, f := range []string{"from", "to", "port"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}

func runTrace(cmd *cobra.Command, path, from, to, protocol string, port int32, output string) error {
	if output != "table" && output != "json" {
		return fmt.Errorf("unknown output format %q (want table or json)", output)
	}
	manifests, err := audit.Load(path)
	if err != nil {
		return err
	}
	src, err := trace.ResolveEndpoint(manifests, from)
	if err != nil {
		return fmt.Errorf("--from: %w", err)
	}
	dst, err := trace.ResolveEndpoint(manifests, to)
	if err != nil {
		return fmt.Errorf("--to: %w", err)
	}
	res, err := trace.Evaluate(manifests, trace.Flow{From: src, To: dst, Protocol: protocol, Port: port})
	if err != nil {
		return err
	}
	if err := trace.Write(cmd.OutOrStdout(), res, output); err != nil {
		return err
	}
	if !res.Allowed {
		return errDenied
	}
	return nil
}
