// Package audit loads Kubernetes manifests and computes NetworkPolicy coverage.
package audit

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/moveeeax/k8s-netpol-coverage/internal/model"
	yamlv3 "gopkg.in/yaml.v3"
	k8syaml "sigs.k8s.io/yaml"
)

// Manifests is the parsed, normalized content of a manifest tree.
type Manifests struct {
	Workloads []model.Workload
	Policies  []model.NetworkPolicy
}

// defaultNamespace matches kubectl's behavior for objects with no namespace set.
const defaultNamespace = "default"

// Load walks root, reading every .yaml/.yml file, and returns the workloads and
// NetworkPolicies it finds. Documents it does not recognize are skipped.
func Load(root string) (*Manifests, error) {
	files, err := yamlFiles(root)
	if err != nil {
		return nil, err
	}
	m := &Manifests{}
	for _, f := range files {
		if err := loadFile(f, m); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
	}
	sort.Slice(m.Workloads, func(i, j int) bool { return less(m.Workloads[i], m.Workloads[j]) })
	sort.Slice(m.Policies, func(i, j int) bool {
		a, b := m.Policies[i], m.Policies[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return m, nil
}

func less(a, b model.Workload) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Name < b.Name
}

func yamlFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".yaml", ".yml":
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func loadFile(path string, m *Manifests) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	docs, err := splitDocuments(raw)
	if err != nil {
		return err
	}
	for _, doc := range docs {
		if err := decodeDoc(doc, path, m); err != nil {
			return err
		}
	}
	return nil
}

// splitDocuments breaks a possibly multi-document YAML stream into the raw bytes
// of each document, using a real YAML parser (not a naive "---" text split).
func splitDocuments(raw []byte) ([][]byte, error) {
	var out [][]byte
	dec := yamlv3.NewDecoder(bytes.NewReader(raw))
	for {
		var node yamlv3.Node
		err := dec.Decode(&node)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if node.Kind == 0 {
			continue // empty document
		}
		buf, err := yamlv3.Marshal(&node)
		if err != nil {
			return nil, err
		}
		out = append(out, buf)
	}
	return out, nil
}

func decodeDoc(doc []byte, path string, m *Manifests) error {
	var tm model.TypeMeta
	if err := k8syaml.Unmarshal(doc, &tm); err != nil {
		return err
	}
	switch tm.Kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Job":
		var c controllerDoc
		if err := k8syaml.Unmarshal(doc, &c); err != nil {
			return err
		}
		m.Workloads = append(m.Workloads, model.Workload{
			Kind:      tm.Kind,
			Name:      c.Metadata.Name,
			Namespace: ns(c.Metadata.Namespace),
			PodLabels: c.Spec.Template.Metadata.Labels,
			File:      path,
		})
	case "Pod":
		var p podDoc
		if err := k8syaml.Unmarshal(doc, &p); err != nil {
			return err
		}
		m.Workloads = append(m.Workloads, model.Workload{
			Kind:      "Pod",
			Name:      p.Metadata.Name,
			Namespace: ns(p.Metadata.Namespace),
			PodLabels: p.Metadata.Labels,
			File:      path,
		})
	case "NetworkPolicy":
		var np netpolDoc
		if err := k8syaml.Unmarshal(doc, &np); err != nil {
			return err
		}
		m.Policies = append(m.Policies, model.NetworkPolicy{
			Name:        np.Metadata.Name,
			Namespace:   ns(np.Metadata.Namespace),
			PodSelector: np.Spec.PodSelector,
			PolicyTypes: effectivePolicyTypes(np),
			HasIngress:  len(np.Spec.Ingress) > 0,
			HasEgress:   len(np.Spec.Egress) > 0,
			File:        path,
		})
	}
	return nil
}

func ns(n string) string {
	if n == "" {
		return defaultNamespace
	}
	return n
}

// effectivePolicyTypes applies the Kubernetes default: Ingress is always set;
// Egress is set when policyTypes omits it but egress rules are present.
func effectivePolicyTypes(np netpolDoc) []string {
	if len(np.Spec.PolicyTypes) > 0 {
		return np.Spec.PolicyTypes
	}
	types := []string{"Ingress"}
	if len(np.Spec.Egress) > 0 {
		types = append(types, "Egress")
	}
	return types
}

// podTemplate is the shared spec.template shape of workload controllers.
type podTemplate struct {
	Metadata model.ObjectMeta `json:"metadata"`
}

// controllerDoc decodes the common controller shape (Deployment, StatefulSet,
// DaemonSet, Job) whose pod labels live under spec.template.metadata.labels.
type controllerDoc struct {
	model.TypeMeta `json:",inline"`
	Metadata       model.ObjectMeta `json:"metadata"`
	Spec           struct {
		Template podTemplate `json:"template"`
	} `json:"spec"`
}

// podDoc decodes a bare Pod, whose labels live on its own metadata.
type podDoc struct {
	model.TypeMeta `json:",inline"`
	Metadata       model.ObjectMeta `json:"metadata"`
}

// netpolDoc decodes a NetworkPolicy manifest.
type netpolDoc struct {
	model.TypeMeta `json:",inline"`
	Metadata       model.ObjectMeta `json:"metadata"`
	Spec           struct {
		PodSelector model.LabelSelector      `json:"podSelector"`
		PolicyTypes []string                 `json:"policyTypes"`
		Ingress     []map[string]interface{} `json:"ingress"`
		Egress      []map[string]interface{} `json:"egress"`
	} `json:"spec"`
}
