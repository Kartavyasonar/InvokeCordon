package policy

// Constants used by the loader, evaluator, and tests
const (
	ModeMonitor = "monitor"
	ModeEnforce = "enforce"

	ActionAllow   = "allow"
	ActionDeny    = "deny"
	ActionMonitor = "monitor"

	RulePathTraversal       = "block_path_traversal"
	RuleShellMetacharacters = "block_shell_metacharacters"
	RuleCloudMetadata       = "block_cloud_metadata"
)

// Policy represents the complete security policy loaded from YAML.
type Policy struct {
	Version       int           `yaml:"version"`
	Mode          string        `yaml:"mode"`           // "monitor" or "enforce"
	DefaultAction string        `yaml:"default_action"` // "allow" or "deny"
	Tools         []ToolRule    `yaml:"tools"`
	ArgumentRules ArgumentRules `yaml:"argument_rules"`
	Redaction     Redaction     `yaml:"redaction"`
	Audit         Audit         `yaml:"audit"`
}

// ToolRule defines the policy for a specific tool.
type ToolRule struct {
	Name               string                   `yaml:"name"`
	Action             string                   `yaml:"action"` // "allow", "deny", or "monitor"
	Reason             string                   `yaml:"reason,omitempty"`
	ProtectedArguments map[string]ProtectedRule `yaml:"protected_arguments,omitempty"`
}

// ProtectedRule defines constraints for application-owned arguments.
type ProtectedRule struct {
	AllowValues  []string `yaml:"allow_values"`
	AllowDomains []string `yaml:"allow_domains"`
}

type ArgumentRules struct {
	BlockPathTraversal       bool `yaml:"block_path_traversal"`
	BlockShellMetacharacters bool `yaml:"block_shell_metacharacters"`
	BlockCloudMetadata       bool `yaml:"block_cloud_metadata"`
}

type Redaction struct {
	RequestFields  []string `yaml:"request_fields"`
	ResponseFields []string `yaml:"response_fields"`
}

type Audit struct {
	LogAllCalls        bool `yaml:"log_all_calls"`
	LogBlockedCalls    bool `yaml:"log_blocked_calls"`
	IncludePayloadHash bool `yaml:"include_payload_hash"`
}

// Decision represents the outcome of a policy evaluation.
type Decision struct {
	Action string // "allow", "deny", or "monitor"
	Reason string
}
