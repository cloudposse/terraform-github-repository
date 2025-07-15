variable "owner" {
  description = "GitHub owner user or organization"
  type        = string
}

variable "repository" {
  description = "Repository configuration"
  type = object({
    name                                    = string
    description                             = optional(string, "Terraform acceptance tests")
    visibility                              = optional(string, "public")
    homepage_url                            = optional(string, "http://example.com/")
    archived                                = optional(bool, false)
    has_issues                              = optional(bool, false)
    has_projects                            = optional(bool, false)
    has_discussions                         = optional(bool, false)
    has_wiki                                = optional(bool, false)
    has_downloads                           = optional(bool, false)
    is_template                             = optional(bool, false)
    allow_squash_merge                      = optional(bool, false)
    squash_merge_commit_title               = optional(string, "PR_TITLE")
    squash_merge_commit_message             = optional(string, "COMMIT_MESSAGE")
    allow_merge_commit                      = optional(bool, false)
    merge_commit_title                      = optional(string, "MERGE_MESSAGE")
    merge_commit_message                    = optional(string, "BLANK")
    allow_rebase_merge                      = optional(bool, false)
    delete_branch_on_merge                  = optional(bool, false)
    default_branch                          = optional(string, "main")
    web_commit_signoff_required             = optional(bool, false)
    topics                                  = optional(list(string), [])
    license_template                        = optional(string, "mit")
    gitignore_template                      = optional(string, "Terraform")
    auto_init                               = optional(bool, false)
    archive_on_destroy                      = optional(bool, false)
    vulnerability_alerts                    = optional(bool, false)
    ignore_vulnerability_alerts_during_read = optional(bool, false)
    allow_update_branch                     = optional(bool, false)
    security_and_analysis = optional(object({
      advanced_security               = bool
      secret_scanning                 = bool
      secret_scanning_push_protection = bool
    }), null)
  })
  default = null
}

variable "autolink_references" {
  description = "Autolink references"
  type = map(object({
    key_prefix          = string
    target_url_template = string
  }))
  default = {}
}

variable "archive_on_destroy" {
  description = "Archive the repository on destroy"
  type        = bool
  default     = false
}

variable "custom_properties" {
  description = "Custom properties for the repository"
  type = map(object({
    string        = optional(string, null)
    boolean       = optional(bool, null)
    single_select = optional(string, null)
    multi_select  = optional(list(string), null)
  }))
  default = null
}

variable "environments" {
  description = "Environments for the repository"
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
  default = null
}

variable "variables" {
  description = "Environment variables for the repository"
  type        = map(string)
  default     = {}
}

variable "secrets" {
  description = "Secrets for the repository"
  type        = map(string)
  default     = {}
}

variable "deploy_keys" {
  description = "Deploy keys for the repository"
  type = map(object({
    title     = string
    key       = string
    read_only = optional(bool, false)
  }))
  default = {}
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
  default = {}
}

variable "labels" {
  description = "A map of labels to configure for the repository"
  type = map(object({
    color       = string
    description = string
  }))
  default = {}
}

variable "teams" {
  description = "A map of teams and their permissions for the repository"
  type        = map(string)
  default     = {}
}

variable "users" {
  description = "A map of users and their permissions for the repository"
  type        = map(string)
  default     = {}
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
      creation         = optional(bool, false),
      deletion         = optional(bool, false),
      non_fast_forward = optional(bool, false),
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
