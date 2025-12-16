owner = "cloudposse-tests"

description                             = "Terraform acceptance tests"
homepage_url                            = "http://example.com/"
archived                                = false
has_issues                              = true
has_discussions                         = true
has_projects                            = true
has_wiki                                = true
has_downloads                           = true
is_template                             = true
allow_merge_commit                      = true
merge_commit_title                      = "MERGE_MESSAGE"
merge_commit_message                    = "PR_TITLE"
allow_squash_merge                      = true
squash_merge_commit_title               = "COMMIT_OR_PR_TITLE"
squash_merge_commit_message             = "COMMIT_MESSAGES"
web_commit_signoff_required             = true
allow_rebase_merge                      = true
allow_auto_merge                        = true
delete_branch_on_merge                  = true
default_branch                          = "main"
gitignore_template                      = "TeX"
license_template                        = "GPL-3.0"
auto_init                               = true
topics                                  = ["terraform", "github", "test"]
ignore_vulnerability_alerts_during_read = true
allow_update_branch                     = true

security_and_analysis = {
  advanced_security               = false
  code_security                   = true
  secret_scanning                 = true
  secret_scanning_push_protection = true
}

# GitHub Pages configuration
pages = {
  build_type = "workflow"
  source = {
    branch = "main"
    path   = "/docs"
  }
}

archive_on_destroy = false

autolink_references = {
  jira = {
    key_prefix          = "JIRA-"
    target_url_template = "https://jira.example.com/browse/<num>"
  }
}

variables = {
  test_variable   = "test-value"
  test_variable_2 = "test-value-2"
}

secrets = {
  test_secret   = "test-value"
  test_secret_2 = "nacl:dGVzdC12YWx1ZS0yCg=="
}

webhooks = {
  notify-on-push = {
    active       = true
    url          = "https://hooks.example.com/github"
    events       = ["push", "pull_request"]
    content_type = "json"
    insecure_ssl = false
    secret       = "test-secret"
  }
}

labels = {
  bug2 = {
    color       = "#a73a4a"
    description = "🐛 An issue with the system"
  }
  feature2 = {
    color       = "#336699"
    description = "New functionality"
  }
}

environments = {
  staging = {
    wait_timer          = 1
    can_admins_bypass   = true
    prevent_self_review = true
    deployment_branch_policy = {
      protected_branches = true
      custom_branches    = null
    }
    variables = {
      test_variable   = "test-value"
      test_variable_2 = "test-value-2"
    }
  }
  development = {
    wait_timer          = 5
    can_admins_bypass   = false
    prevent_self_review = false
    variables           = {}
  }
  production = {
    wait_timer          = 10
    can_admins_bypass   = false
    prevent_self_review = false
    deployment_branch_policy = {
      protected_branches = false
      custom_branches = {
        branches = ["main"]
        tags     = ["v1.0.0"]
      }
    }
    secrets = {
      test_secret   = "test-value"
      test_secret_2 = "nacl:dGVzdC12YWx1ZS0yCg=="
    }
  }
}

rulesets = {
  default = {
    name        = "Default protection"
    enforcement = "active"
    target      = "branch"
    conditions = {
      ref_name = {
        include = ["~ALL"]
        exclude = [
          "refs/heads/releases",
          "main"
        ]
      }
    }
    bypass_actors = [
      {
        bypass_mode = "always"
        actor_type  = "OrganizationAdmin"
      },
      {
        bypass_mode = "pull_request"
        actor_type  = "RepositoryRole"
        actor_id    = "maintain"
      },
      {
        bypass_mode = "pull_request"
        actor_type  = "RepositoryRole"
        actor_id    = "write"
      },
      {
        bypass_mode = "pull_request"
        actor_type  = "RepositoryRole"
        actor_id    = "admin"
      }
    ]
    rules = {
      branch_name_pattern = {
        operator = "starts_with"
        pattern  = "release"
        name     = "Release branch"
        negate   = false
      }
      commit_author_email_pattern = {
        operator = "contains"
        pattern  = "gmail.com"
        name     = "Gmail email"
        negate   = true
      }
      commit_message_pattern = {
        operator = "ends_with"
        pattern  = "test"
        name     = "Test message"
        negate   = false
      }
      committer_email_pattern = {
        operator = "contains"
        pattern  = "test@example.com"
        name     = "Test committer email"
        negate   = false
      }
      creation                      = true
      deletion                      = false
      non_fast_forward              = true
      required_linear_history       = true
      required_signatures           = false
      update                        = true
      update_allows_fetch_and_merge = true
      pull_request = {
        dismiss_stale_reviews_on_push     = true
        require_code_owner_review         = true
        require_last_push_approval        = true
        required_approving_review_count   = 1
        required_review_thread_resolution = true
      }
      required_deployments = {
        required_deployment_environments = [
          "staging",
          "production"
        ]
      }
      required_status_checks = {
        required_check = [
          {
            context = "test"
          }
        ]
        strict_required_status_checks_policy = true
        do_not_enforce_on_create             = true
      }
      required_code_scanning = {
        required_code_scanning_tool = [
          {
            alerts_threshold          = "errors"
            security_alerts_threshold = "high_or_higher"
            tool                      = "CodeQL"
          }
        ]
      }
    }
  }
  tag_protection = {
    name        = "Tag protection"
    enforcement = "active"
    target      = "tag"
    conditions = {
      ref_name = {
        include = ["~ALL"]
        exclude = []
      }
    }
    bypass_actors = [
      {
        bypass_mode = "always"
        actor_type  = "OrganizationAdmin"
      }
    ]
    rules = {
      tag_name_pattern = {
        operator = "starts_with"
        pattern  = "v"
        name     = "Semantic version tags"
        negate   = false
      }
      creation = true
      deletion = true
    }
  }
  push_restrictions = {
    name        = "Push restrictions"
    enforcement = "evaluate"
    target      = "push"
    conditions = {
      ref_name = {
        include = ["~ALL"]
        exclude = []
      }
    }
    bypass_actors = [
      {
        bypass_mode = "always"
        actor_type  = "OrganizationAdmin"
      }
    ]
    rules = {
      file_path_restriction = {
        restricted_file_paths = [
          ".github/workflows/*",
          "terraform/*"
        ]
      }
      max_file_size = {
        max_file_size = 50
      }
      max_file_path_length = {
        max_file_path_length = 256
      }
      file_extension_restriction = {
        restricted_file_extensions = [
          ".exe",
          ".dll",
          ".so"
        ]
      }
    }
  }
}
