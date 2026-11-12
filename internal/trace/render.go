package trace

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Write renders the result in the given format ("table" or "json").
func Write(w io.Writer, r Result, format string) error {
	switch format {
	case "table", "":
		return writeTable(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	default:
		return fmt.Errorf("unknown output format %q (want table or json)", format)
	}
}

func verdict(allowed bool) string {
	if allowed {
		return "ALLOWED"
	}
	return "DENIED"
}

func writeTable(w io.Writer, r Result) error {
	fmt.Fprintf(w, "%s -> %s %s/%d\n\n", r.From, r.To, r.Protocol, r.Port)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "DIRECTION\tVERDICT\tDECISION\tMESSAGE")
	for _, s := range []Step{r.Egress, r.Ingress} {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", strings.ToUpper(s.Direction), verdict(s.Allowed), s.Decision, s.Message)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\nVerdict: %s\n", verdict(r.Allowed))
	return nil
}
