package model

// Matches reports whether the selector selects a pod carrying the given labels.
// An empty selector ({}) selects everything, matching Kubernetes semantics.
func (s *LabelSelector) Matches(labels map[string]string) bool {
	if s.IsEmpty() {
		return true
	}
	for k, v := range s.MatchLabels {
		if labels[k] != v {
			return false
		}
	}
	for _, req := range s.MatchExpressions {
		if !req.matches(labels) {
			return false
		}
	}
	return true
}

func (r LabelSelectorRequirement) matches(labels map[string]string) bool {
	val, present := labels[r.Key]
	switch r.Operator {
	case "In":
		return present && contains(r.Values, val)
	case "NotIn":
		return !present || !contains(r.Values, val)
	case "Exists":
		return present
	case "DoesNotExist":
		return !present
	default:
		// Unknown operator: treat as non-matching so we never overstate coverage.
		return false
	}
}

func contains(vals []string, want string) bool {
	for _, v := range vals {
		if v == want {
			return true
		}
	}
	return false
}
