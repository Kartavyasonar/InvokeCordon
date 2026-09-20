package policy

import (
	"fmt"
	"strings"
)

// Evaluate checks tool rules, protected arguments, and generic argument rules.
func Evaluate(toolName string, arguments map[string]any, p Policy) Decision {
	// 1. Find tool rule
	var toolRule *ToolRule
	for i := range p.Tools {
		if p.Tools[i].Name == toolName {
			toolRule = &p.Tools[i]
			break
		}
	}

	// 2. Determine base action
	action := p.DefaultAction
	reason := fmt.Sprintf("default action is %s", action)
	if toolRule != nil {
		action = toolRule.Action
		if toolRule.Reason != "" {
			reason = toolRule.Reason
		} else {
			reason = fmt.Sprintf("tool %q is %s by policy", toolName, action)
		}
	}

	// If base action is explicitly deny, return immediately
	if action == ActionDeny {
		return Decision{Action: ActionDeny, Reason: reason}
	}

	// 3. Check Protected Arguments (Tier 1)
	// These override "allow" if the value is not in the allowlist.
	if toolRule != nil && toolRule.ProtectedArguments != nil && arguments != nil {
		for argName, rule := range toolRule.ProtectedArguments {
			val, exists := arguments[argName]
			if !exists {
				continue // Missing protected argument is allowed (optional)
			}

			strVal, ok := val.(string)
			if !ok {
				return makeViolation(p.Mode, fmt.Sprintf("Protected argument violated: %s must be a string", argName))
			}

			allowed := false

			// Check exact values
			for _, v := range rule.AllowValues {
				if strVal == v {
					allowed = true
					break
				}
			}

			// Check domains (for emails)
			if !allowed && strings.Contains(strVal, "@") {
				parts := strings.Split(strVal, "@")
				if len(parts) == 2 {
					domain := strings.ToLower(strings.TrimSpace(parts[1]))
					for _, d := range rule.AllowDomains {
						if domain == strings.ToLower(d) {
							allowed = true
							break
						}
					}
				}
			}

			if !allowed {
				return makeViolation(p.Mode, fmt.Sprintf("Protected argument violated: %s", argName))
			}
		}
	}

	// 4. Check Generic Argument Rules
	if arguments != nil {
		if p.ArgumentRules.BlockPathTraversal && checkMap(arguments, isPathTraversal) {
			return makeViolation(p.Mode, "Argument violated rule: "+RulePathTraversal)
		}
		if p.ArgumentRules.BlockShellMetacharacters && checkMap(arguments, isShellInjection) {
			return makeViolation(p.Mode, "Argument violated rule: "+RuleShellMetacharacters)
		}
		if p.ArgumentRules.BlockCloudMetadata && checkMap(arguments, isCloudMetadata) {
			return makeViolation(p.Mode, "Argument violated rule: "+RuleCloudMetadata)
		}
	}

	// 5. Return base action
	return Decision{Action: action, Reason: reason}
}

func makeViolation(mode string, reason string) Decision {
	if mode == ModeEnforce {
		return Decision{Action: ActionDeny, Reason: reason}
	}
	return Decision{Action: ActionMonitor, Reason: reason}
}

// --- Helper Functions for Argument Checking ---

type checker func(string) bool

func checkMap(m map[string]any, check checker) bool {
	for _, v := range m {
		if checkValue(v, check) {
			return true
		}
	}
	return false
}

func checkValue(v any, check checker) bool {
	switch val := v.(type) {
	case string:
		if check(val) {
			return true
		}
	case map[string]any:
		if checkMap(val, check) {
			return true
		}
	case []any:
		for _, item := range val {
			if checkValue(item, check) {
				return true
			}
		}
	}
	return false
}

func isPathTraversal(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "../") ||
		strings.Contains(lower, "..\\") ||
		strings.Contains(lower, "..%2f") ||
		strings.Contains(lower, "%2e%2e%2f") ||
		strings.Contains(lower, "/etc/passwd") ||
		strings.Contains(lower, "/etc/shadow")
}

func isShellInjection(s string) bool {
	lower := strings.ToLower(s)
	// Common metacharacters
	if strings.ContainsAny(s, ";|&`$()") {
		return true
	}
	// Common dangerous commands
	dangerous := []string{"rm ", "curl ", "wget ", "bash ", "sh ", "nc ", "python ", "perl "}
	for _, cmd := range dangerous {
		if strings.Contains(lower, cmd) {
			return true
		}
	}
	return false
}

func isCloudMetadata(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "169.254.169.254") ||
		strings.Contains(lower, "metadata.google.internal")
}
