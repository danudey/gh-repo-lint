// Package ghdata contains the GitHub API response types and the collector that
// gathers everything the linter needs about a repository in one pass.
package ghdata

import "time"

// Repo is the subset of the repository object the checks care about.
type Repo struct {
	FullName      string `json:"full_name"`
	Name          string `json:"name"`
	Private       bool   `json:"private"`
	Visibility    string `json:"visibility"`
	Archived      bool   `json:"archived"`
	Disabled      bool   `json:"disabled"`
	Fork          bool   `json:"fork"`
	IsTemplate    bool   `json:"is_template"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
	License *struct {
		SPDXID string `json:"spdx_id"`
	} `json:"license"`
	Permissions struct {
		Admin bool `json:"admin"`
		Push  bool `json:"push"`
	} `json:"permissions"`

	AllowForking             bool `json:"allow_forking"`
	AllowSquashMerge         bool `json:"allow_squash_merge"`
	AllowMergeCommit         bool `json:"allow_merge_commit"`
	AllowRebaseMerge         bool `json:"allow_rebase_merge"`
	AllowAutoMerge           bool `json:"allow_auto_merge"`
	DeleteBranchOnMerge      bool `json:"delete_branch_on_merge"`
	WebCommitSignoffRequired bool `json:"web_commit_signoff_required"`

	SecurityAndAnalysis *SecurityAndAnalysis `json:"security_and_analysis"`
}

// SecurityAndAnalysis is only returned to callers with admin on the repository.
type SecurityAndAnalysis struct {
	AdvancedSecurity                  *StatusField `json:"advanced_security"`
	SecretScanning                    *StatusField `json:"secret_scanning"`
	SecretScanningPushProtection      *StatusField `json:"secret_scanning_push_protection"`
	SecretScanningValidityChecks      *StatusField `json:"secret_scanning_validity_checks"`
	SecretScanningNonProviderPatterns *StatusField `json:"secret_scanning_non_provider_patterns"`
	DependabotSecurityUpdates         *StatusField `json:"dependabot_security_updates"`
}

type StatusField struct {
	Status string `json:"status"`
}

// Enabled reports whether a security_and_analysis sub-field is switched on.
func (s *StatusField) Enabled() bool { return s != nil && s.Status == "enabled" }

// Ruleset is a repository or organization ruleset. Rules and BypassActors are
// only populated after fetching the ruleset detail endpoint.
type Ruleset struct {
	ID           int64             `json:"id"`
	Name         string            `json:"name"`
	Target       string            `json:"target"` // branch | tag | push | repository
	SourceType   string            `json:"source_type"`
	Source       string            `json:"source"`
	Enforcement  string            `json:"enforcement"` // active | evaluate | disabled
	Conditions   *RulesetCondition `json:"conditions"`
	Rules        []Rule            `json:"rules"`
	BypassActors []BypassActor     `json:"bypass_actors"`
	Links        struct {
		HTML struct {
			HRef string `json:"href"`
		} `json:"html"`
	} `json:"_links"`
}

type RulesetCondition struct {
	RefName *struct {
		Include []string `json:"include"`
		Exclude []string `json:"exclude"`
	} `json:"ref_name"`
	RepositoryName *struct {
		Include []string `json:"include"`
		Exclude []string `json:"exclude"`
	} `json:"repository_name"`
}

type BypassActor struct {
	ActorID    int64  `json:"actor_id"`
	ActorType  string `json:"actor_type"` // RepositoryRole | Team | Integration | OrganizationAdmin | DeployKey
	BypassMode string `json:"bypass_mode"`
}

// Rule keeps its parameters as raw JSON so each check can decode only the
// parameter shape it understands.
type Rule struct {
	Type              string `json:"type"`
	Parameters        RawMsg `json:"parameters"`
	RulesetSourceType string `json:"ruleset_source_type"`
	RulesetSource     string `json:"ruleset_source"`
	RulesetID         int64  `json:"ruleset_id"`
}

// PullRequestParams are the parameters of a `pull_request` ruleset rule.
type PullRequestParams struct {
	RequiredApprovingReviewCount   int      `json:"required_approving_review_count"`
	DismissStaleReviewsOnPush      bool     `json:"dismiss_stale_reviews_on_push"`
	RequireCodeOwnerReview         bool     `json:"require_code_owner_review"`
	RequireLastPushApproval        bool     `json:"require_last_push_approval"`
	RequiredReviewThreadResolution bool     `json:"required_review_thread_resolution"`
	AllowedMergeMethods            []string `json:"allowed_merge_methods"`
}

// StatusChecksParams are the parameters of a `required_status_checks` rule.
type StatusChecksParams struct {
	StrictRequiredStatusChecksPolicy bool `json:"strict_required_status_checks_policy"`
	DoNotEnforceOnCreate             bool `json:"do_not_enforce_on_create"`
	RequiredStatusChecks             []struct {
		Context       string `json:"context"`
		IntegrationID *int64 `json:"integration_id"`
	} `json:"required_status_checks"`
}

// CodeScanningParams are the parameters of a `code_scanning` rule.
type CodeScanningParams struct {
	CodeScanningTools []struct {
		Tool                    string `json:"tool"`
		SecurityAlertsThreshold string `json:"security_alerts_threshold"`
		AlertsThreshold         string `json:"alerts_threshold"`
	} `json:"code_scanning_tools"`
}

// CodeQualityParams are the parameters of a `code_quality` rule.
type CodeQualityParams struct {
	Severity string `json:"severity"`
}

// BranchProtection is the classic (pre-ruleset) branch protection object.
type BranchProtection struct {
	URL                  string `json:"url"`
	RequiredStatusChecks *struct {
		Strict   bool     `json:"strict"`
		Contexts []string `json:"contexts"`
	} `json:"required_status_checks"`
	RequiredPullRequestReviews *struct {
		DismissStaleReviews          bool `json:"dismiss_stale_reviews"`
		RequireCodeOwnerReviews      bool `json:"require_code_owner_reviews"`
		RequiredApprovingReviewCount int  `json:"required_approving_review_count"`
		RequireLastPushApproval      bool `json:"require_last_push_approval"`
	} `json:"required_pull_request_reviews"`
	EnforceAdmins *struct {
		Enabled bool `json:"enabled"`
	} `json:"enforce_admins"`
	RequiredSignatures *struct {
		Enabled bool `json:"enabled"`
	} `json:"required_signatures"`
	RequiredLinearHistory *struct {
		Enabled bool `json:"enabled"`
	} `json:"required_linear_history"`
	AllowForcePushes *struct {
		Enabled bool `json:"enabled"`
	} `json:"allow_force_pushes"`
	AllowDeletions *struct {
		Enabled bool `json:"enabled"`
	} `json:"allow_deletions"`
	RequiredConversationResolution *struct {
		Enabled bool `json:"enabled"`
	} `json:"required_conversation_resolution"`
	BlockCreations *struct {
		Enabled bool `json:"enabled"`
	} `json:"block_creations"`
	Restrictions *struct {
		Users []struct {
			Login string `json:"login"`
		} `json:"users"`
		Teams []struct {
			Slug string `json:"slug"`
		} `json:"teams"`
		Apps []struct {
			Slug string `json:"slug"`
		} `json:"apps"`
	} `json:"restrictions"`
}

type Branch struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
}

// ActionsPermissions is GET /repos/{o}/{r}/actions/permissions.
type ActionsPermissions struct {
	Enabled            bool   `json:"enabled"`
	AllowedActions     string `json:"allowed_actions"` // all | local_only | selected
	SHAPinningRequired bool   `json:"sha_pinning_required"`
}

// WorkflowPermissions is GET /repos/{o}/{r}/actions/permissions/workflow.
type WorkflowPermissions struct {
	DefaultWorkflowPermissions string `json:"default_workflow_permissions"` // read | write
	CanApprovePullRequests     bool   `json:"can_approve_pull_request_reviews"`
}

type AutomatedSecurityFixes struct {
	Enabled bool `json:"enabled"`
	Paused  bool `json:"paused"`
}

type CodeScanningDefaultSetup struct {
	State      string   `json:"state"` // configured | not-configured
	Languages  []string `json:"languages"`
	QuerySuite string   `json:"query_suite"`
}

type CodeScanningAnalysis struct {
	Tool struct {
		Name string `json:"name"`
	} `json:"tool"`
	CreatedAt time.Time `json:"created_at"`
}

type ImmutableReleases struct {
	Enabled         bool `json:"enabled"`
	EnforcedByOwner bool `json:"enforced_by_owner"`
}

type EnabledFlag struct {
	Enabled bool `json:"enabled"`
}

type Collaborator struct {
	Login    string `json:"login"`
	Type     string `json:"type"`
	RoleName string `json:"role_name"`
}

type Team struct {
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	Permission string `json:"permission"`
}

type DeployKey struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	ReadOnly bool   `json:"read_only"`
}

type Environment struct {
	Name            string `json:"name"`
	ProtectionRules []struct {
		Type      string `json:"type"` // required_reviewers | wait_timer | branch_policy
		Reviewers []struct {
			Type string `json:"type"`
		} `json:"reviewers"`
	} `json:"protection_rules"`
	DeploymentBranchPolicy *struct {
		ProtectedBranches    bool `json:"protected_branches"`
		CustomBranchPolicies bool `json:"custom_branch_policies"`
	} `json:"deployment_branch_policy"`
}

type environmentsResponse struct {
	TotalCount   int           `json:"total_count"`
	Environments []Environment `json:"environments"`
}

type WorkflowMeta struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
}

type workflowsResponse struct {
	TotalCount int            `json:"total_count"`
	Workflows  []WorkflowMeta `json:"workflows"`
}

type treeResponse struct {
	Truncated bool `json:"truncated"`
	Tree      []struct {
		Path string `json:"path"`
		Type string `json:"type"`
		Size int    `json:"size"`
	} `json:"tree"`
}

type contentResponse struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Size     int    `json:"size"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}
