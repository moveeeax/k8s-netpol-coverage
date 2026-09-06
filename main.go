// Command k8s-netpol-coverage statically audits Kubernetes manifests for
// NetworkPolicy coverage gaps: workloads no policy selects, namespaces with no
// default-deny, and policies whose selectors match nothing.
package main

import "github.com/moveeeax/k8s-netpol-coverage/cmd"

func main() {
	cmd.Execute()
}
