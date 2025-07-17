variable "owner" {
  description = "Owner of the repository"
  type        = string
}

variable "template" {
  description = "Template repository"
  type = object({
    owner = string
    name = string
    include_all_branches = optional(bool, false)
  })
  default = null
}

variable "description" {
  description = "Description of the repository"
  type        = string
  default     = null
}

variable "visibility" {
  description = "Visibility of the repository. Must be public, private, or internal."
  type        = string
  default     = "public"

  validation {
    condition     = contains(["public", "private", "internal"], var.visibility)
    error_message = "Repository visibility must be public, private or internal"
  }
}

variable "homepage_url" {
  description = "Homepage URL of the repository"
  type        = string
  default     = null
}

variable "archived" {
  description = "Whether the repository is archived"
  type        = bool
  default     = false
}

variable "has_issues" {
  description = "Whether the repository has issues enabled"
  type        = bool
  default     = false
}

variable "has_projects" {
  description = "Whether the repository has projects enabled"
  type        = bool
  default     = false
}

variable "has_discussions" {
  description = "Whether the repository has discussions enabled"
  type        = bool
  default     = false
}

variable "has_wiki" {
  description = "Whether the repository has wiki enabled"
  type        = bool
  default     = false
}

variable "has_downloads" {
  description = "Whether the repository has downloads enabled"
  type        = bool
  default     = false
}

variable "is_template" {
  description = "Whether the repository is a template"
  type        = bool
  default     = false
}

variable "allow_squash_merge" {
  description = "Allow squash merge"
  type        = bool
  default     = true
}

variable "squash_merge_commit_title" {
  description = "Squash merge commit title. Must be PR_TITLE or COMMIT_OR_PR_TITLE."
  type        = string
  default     = "PR_TITLE"

  validation {
    condition     = contains(["PR_TITLE", "COMMIT_OR_PR_TITLE"], var.squash_merge_commit_title)
    error_message = "Repository squash merge commit title must be PR_TITLE, COMMIT_OR_PR_TITLE"
  }
}

variable "squash_merge_commit_message" {
  description = "Squash merge commit message. Must be PR_BODY, COMMIT_MESSAGES or BLANK."
  type        = string
  default     = "COMMIT_MESSAGES"

  validation {
    condition     = contains(["PR_BODY", "COMMIT_MESSAGES", "BLANK"], var.squash_merge_commit_message)
    error_message = "Repository squash merge commit message must be PR_BODY, COMMIT_MESSAGES or BLANK"
  }
}

variable "allow_merge_commit" {
  description = "Allow merge commit"
  type        = bool
  default     = true
}

variable "merge_commit_title" {
  description = "Merge commit title. Must be PR_TITLE or MERGE_MESSAGE."
  type        = string
  default     = "PR_TITLE"

  validation {
    condition     = contains(["PR_TITLE", "MERGE_MESSAGE"], var.merge_commit_title)
    error_message = "Repository merge commit title must be PR_TITLE, MERGE_MESSAGE"
  }
}

variable "merge_commit_message" {
  description = "Merge commit message. Must be PR_BODY, PR_TITLE or BLANK."
  type        = string
  default     = "PR_BODY"

  validation {
    condition     = contains(["PR_BODY", "PR_TITLE", "BLANK"], var.merge_commit_message)
    error_message = "Repository merge commit message must be PR_BODY, PR_TITLE or BLANK"
  }
}

variable "allow_auto_merge" {
  description = "Allow auto merge"
  type        = bool
  default     = false
}

variable "allow_rebase_merge" {
  description = "Allow rebase merge"
  type        = bool
  default     = true
}

variable "delete_branch_on_merge" {
  description = "Delete branch on merge"
  type        = bool
  default     = false
}

variable "default_branch" {
  description = "Default branch name"
  type        = string
  default     = "main"
}

variable "web_commit_signoff_required" {
  description = "Require signoff on web commits"
  type        = bool
  default     = false
}

variable "topics" {
  description = "List of repository topics"
  type        = list(string)
  default     = []
}

variable "license_template" {
  description = "License template"
  type        = string
  default     = null
}

variable "gitignore_template" {
  description = "Gitignore template"
  type        = string
  default     = null
}

variable "auto_init" {
  description = "Auto-initialize the repository"
  type        = bool
  default     = false
}

variable "ignore_vulnerability_alerts_during_read" {
  description = "Ignore vulnerability alerts during read"
  type        = bool
  default     = false
}

variable "enable_vulnerability_alerts" {
  description = "Enable vulnerability alerts"
  type        = bool
  default     = true
}

variable "allow_update_branch" {
  description = "Allow updating the branch"
  type        = bool
  default     = false
}

variable "security_and_analysis" {
  description = "Security and analysis settings"
  type = object({
    advanced_security               = bool
    secret_scanning                 = bool
    secret_scanning_push_protection = bool
  })
  default = null
}

variable "archive_on_destroy" {
  description = "Archive the repository on destroy"
  type        = bool
  default     = false
}

variable "autolink_references" {
  description = "Autolink references"
  type = map(object({
    key_prefix          = string
    target_url_template = string
    is_alphanumeric     = optional(bool, false)
  }))
  default  = {}
  nullable = false

  validation {
    condition     = alltrue([for k, v in var.autolink_references : can(regex("^http(s)?://", v.target_url_template))])
    error_message = "Autolink reference target URL template must start with http:// or https://"
  }

  validation {
    condition     = alltrue([for k, v in var.autolink_references : can(strcontains(v.key_prefix, "<num>"))])
    error_message = "Autolink reference key prefix must contain <num>"
  }
}

variable "custom_properties" {
  description = "Custom properties for the repository"
  type = map(object({
    string        = optional(string, null)
    boolean       = optional(bool, null)
    single_select = optional(string, null)
    multi_select  = optional(list(string), null)
  }))
  default  = {}
  nullable = false

  validation {
    condition     = alltrue([for k, v in var.custom_properties : length([for n, i in v : n if i != null]) == 1])
    error_message = "Custom property must have only one of the following: string, boolean, single_select, multi_select"
  }
}

variable "environments" {
  description = "Environments for the repository. Enviroment secrets should be encrypted using the GitHub public key in Base64 format if prefixed with nacl:. Read more: https://docs.github.com/en/actions/security-for-github-actions/encrypted-secrets"
  type = map(object({
    wait_timer          = optional(number, 0)
    can_admins_bypass   = optional(bool, false)
    prevent_self_review = optional(bool, false)
    reviewers = optional(object({
      teams = optional(list(string), [])
      users = optional(list(string), [])
    }), null)
    deployment_branch_policy = optional(object({
      protected_branches = optional(bool, false)
      custom_branches = optional(object({
        branches = optional(list(string), null)
        tags     = optional(list(string), null)
      }), null)
    }), null)
    variables = optional(map(string), null)
    secrets   = optional(map(string), null)
  }))
  default   = {}
  sensitive = true
  nullable  = false

  validation {
    condition     = alltrue([for k, v in var.environments : try(length(v.reviewers.teams) <= 6, true)])
    error_message = "Environment reviewers can not have more than 6 teams"
  }

  validation {
    condition     = alltrue([for k, v in var.environments : try(length(v.reviewers.users) <= 6, true)])
    error_message = "Environment reviewers can not have more than 6 users"
  }

  validation {
    condition     = alltrue([for k, v in var.environments : try(v.deployment_branch_policy.protected_branches == true || v.deployment_branch_policy.custom_branches != null, true)])
    error_message = "Environment deployment branch policy should have protected_branches set to true or custom_branches specified"
  }

  validation {
    condition     = alltrue([for k, v in var.environments : try(alltrue([for k, v in v.variables : can(regex("^[a-zA-Z0-9_]+$", k))]), true)])
    error_message = "Environment variables must be alphanumeric and underscores only, can not start with a number"
  }

  validation {
    condition     = alltrue([for k, v in var.environments : try(alltrue([for k, v in v.secrets : can(regex("^[a-zA-Z0-9_]+$", k))]), true)])
    error_message = "Environment secrets must be alphanumeric and underscores only, can not start with a number"
  }
}


variable "variables" {
  description = "Environment variables for the repository"
  type        = map(string)
  default     = {}
  nullable    = false

  validation {
    condition     = var.variables == null || alltrue([for k, v in var.variables : can(regex("^[a-zA-Z0-9_]+$", k))])
    error_message = "Variable names must be alphanumeric and underscores only, can not start with a number"
  }
}

variable "secrets" {
  description = "Secrets for the repository (if prefixed with nacl: it should be encrypted value using the GitHub public key in Base64 format. Read more: https://docs.github.com/en/actions/security-for-github-actions/encrypted-secrets)"
  type        = map(string)
  default     = {}
  sensitive   = true
  nullable    = false

  validation {
    condition     = var.secrets == null || alltrue([for k, v in var.secrets : can(regex("^[a-zA-Z0-9_]+$", k))])
    error_message = "Secret names must be alphanumeric and underscores only, can not start with a number"
  }
}

variable "deploy_keys" {
  description = "Deploy keys for the repository"
  type = map(object({
    title     = string
    key       = string
    read_only = optional(bool, false)
  }))
  default  = {}
  nullable = false
}

// https://docs.github.com/en/webhooks/webhook-events-and-payloads
variable "webhooks" {
  description = "A map of webhooks to configure for the repository"
  type = map(object({
    active       = optional(bool, true)
    events       = list(string)
    url          = string
    content_type = optional(string, "json")
    insecure_ssl = optional(bool, false)
    secret       = optional(string, null)
  }))
  default  = {}
  nullable = false

  validation {
    condition     = alltrue([for k, v in var.webhooks : can(regex("^http(s)?://", v.url))])
    error_message = "Webhook URL must start with http:// or https://"
  }

  validation {
    condition     = alltrue([for k, v in var.webhooks : contains(["json", "form"], v.content_type)])
    error_message = "Webhook content type must be json or form"
  }
}

variable "labels" {
  description = "A map of labels to configure for the repository"
  type = map(object({
    color       = string
    description = string
  }))
  default  = {}
  nullable = false
}

variable "teams" {
  description = "A map of teams and their permissions for the repository"
  type        = map(string)
  default     = {}
  nullable    = false
}

variable "users" {
  description = "A map of users and their permissions for the repository"
  type        = map(string)
  default     = {}
  nullable    = false
}

variable "rulesets" {
  description = "A map of rulesets to configure for the repository"
  type = map(object({
    name        = string
    enforcement = string // disabled, active
    target      = string // branch, tag
    bypass_actors = optional(list(object({
      // always, pull_request
      bypass_mode = string
      actor_id    = optional(string, null)
      // RepositoryRole, Team, Integration, OrganizationAdmin
      actor_type = string
    })), [])
    conditions = object({
      ref_name = object({
        include = optional(list(string), []) // ~DEFAULT_BRANCH to include the default branch or ~ALL
        exclude = optional(list(string), []) // ~DEFAULT_BRANCH to exclude the default branch or ~ALL
      })
    })
    rules = object({
      branch_name_pattern = optional(object({
        operator = string // starts_with, ends_with, contains, equals
        pattern  = string
        name     = optional(string, null)
        negate   = optional(bool, false)
      }), null),
      commit_author_email_pattern = optional(object({
        operator = string // starts_with, ends_with, contains, equals
        pattern  = string
        name     = optional(string, null)
        negate   = optional(bool, false)
      }), null),
      creation         = optional(bool, false),
      deletion         = optional(bool, false),
      non_fast_forward = optional(bool, false),
      required_pull_request_reviews = optional(object({
        dismiss_stale_reviews           = bool
        required_approving_review_count = number
      }), null),
      commit_message_pattern = optional(object({
        operator = string // starts_with, ends_with, contains, equals
        pattern  = string
        name     = optional(string, null)
        negate   = optional(bool, false)
      }), null),
      committer_email_pattern = optional(object({
        operator = string // starts_with, ends_with, contains, equals
        pattern  = string
        name     = optional(string, null)
        negate   = optional(bool, false)
      }), null),
      merge_queue = optional(object({
        check_response_timeout_minutes    = optional(number, 60)
        grouping_strategy                 = string // ALLGREEN, HEADGREEN
        max_entries_to_build              = optional(number, 5)
        max_entries_to_merge              = optional(number, 5)
        merge_method                      = optional(string, "MERGE") // MERGE, SQUASH, REBASE
        min_entries_to_merge              = optional(number, 1)
        min_entries_to_merge_wait_minutes = optional(number, 5)
      }), null),
      pull_request = optional(object({
        dismiss_stale_reviews_on_push     = optional(bool, false)
        require_code_owner_review         = optional(bool, false)
        require_last_push_approval        = optional(bool, false)
        required_approving_review_count   = optional(number, 0)
        required_review_thread_resolution = optional(bool, false)
      }), null),
      required_deployments = optional(object({
        required_deployment_environments = optional(list(string), [])
      }), null),
      required_status_checks = optional(object({
        required_check = list(object({
          context        = string
          integration_id = optional(number, null)
        }))
        strict_required_status_checks_policy = optional(bool, false)
        do_not_enforce_on_create             = optional(bool, false)
      }), null),
      tag_name_pattern = optional(object({
        operator = string // starts_with, ends_with, contains, equals
        pattern  = string
        name     = optional(string, null)
        negate   = optional(bool, false)
      }), null),
      // Unsupported due to drift. https://github.com/integrations/terraform-provider-github/pull/2701
      # required_code_scanning = optional(object({
      #   required_code_scanning_tool = list(object({
      #     alerts_threshold          = string // none, errors, errors_and_warnings, all
      #     security_alerts_threshold = string // none, critical, high_or_higher, medium_or_higher, all
      #     tool                      = string
      #   }))
      # }), null),
    }),
  }))
  default = {}
}
