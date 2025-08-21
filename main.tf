resource "github_repository" "default" {
  count = module.this.enabled ? 1 : 0

  name        = module.this.id
  description = var.description
  visibility  = var.visibility

  homepage_url = var.homepage_url
  topics       = var.topics

  dynamic "template" {
    for_each = var.template != null ? [var.template] : []
    content {
      repository           = template.value.name
      owner                = template.value.owner
      include_all_branches = template.value.include_all_branches
    }
  }

  archived           = var.archived
  archive_on_destroy = var.archive_on_destroy

  is_template = var.is_template

  has_discussions = var.has_discussions
  has_downloads   = var.has_downloads
  has_issues      = var.has_issues
  has_projects    = var.has_projects
  has_wiki        = var.has_wiki

  allow_squash_merge = var.allow_squash_merge
  allow_merge_commit = var.allow_merge_commit
  allow_rebase_merge = var.allow_rebase_merge

  squash_merge_commit_title   = var.squash_merge_commit_title
  squash_merge_commit_message = var.squash_merge_commit_message

  allow_auto_merge = var.allow_auto_merge

  merge_commit_title   = var.merge_commit_title
  merge_commit_message = var.merge_commit_message

  allow_update_branch    = var.allow_update_branch
  delete_branch_on_merge = var.delete_branch_on_merge

  auto_init          = var.auto_init
  gitignore_template = var.gitignore_template
  license_template   = var.license_template

  web_commit_signoff_required = var.web_commit_signoff_required

  vulnerability_alerts = var.visibility != "public" ? var.enable_vulnerability_alerts : true

  ignore_vulnerability_alerts_during_read = var.ignore_vulnerability_alerts_during_read

  dynamic "security_and_analysis" {
    for_each = var.security_and_analysis != null ? [var.security_and_analysis] : []
    content {
      dynamic "advanced_security" {
        for_each = var.visibility != "public" && security_and_analysis.value.advanced_security ? [1] : []
        content {
          status = "enabled"
        }
      }
      secret_scanning {
        status = security_and_analysis.value.secret_scanning ? "enabled" : "disabled"
      }
      secret_scanning_push_protection {
        status = security_and_analysis.value.secret_scanning_push_protection ? "enabled" : "disabled"
      }
    }
  }

  lifecycle {
    ignore_changes = [
      template[0].include_all_branches,
    ]
  }
}

resource "github_branch_default" "default" {
  count = module.this.enabled && var.auto_init ? 1 : 0

  repository = join("", github_repository.default[*].name)
  branch     = var.default_branch

  depends_on = [
    github_repository.default
  ]
}

resource "github_repository_autolink_reference" "default" {
  for_each = module.this.enabled ? var.autolink_references : {}

  repository = join("", github_repository.default[*].name)

  key_prefix = each.value.key_prefix

  target_url_template = each.value.target_url_template
}


resource "github_repository_custom_property" "default" {
  for_each = module.this.enabled ? var.custom_properties : {}

  repository    = join("", github_repository.default[*].name)
  property_name = each.key
  property_type = coalesce(
    each.value.string != null ? "string" :
    each.value.boolean != null ? "true_false" :
    each.value.single_select != null ? "single_select" :
    each.value.multi_select != null ? "multi_select" :
    null
  )
  property_value = compact(coalesce(
    each.value.string != null ? [each.value.string] :
    each.value.boolean != null ? [tostring(each.value.boolean)] :
    each.value.single_select != null ? [each.value.single_select] :
    each.value.multi_select != null ? each.value.multi_select :
    []
  ))
}

locals {
  environments = module.this.enabled ? {
    for k, v in nonsensitive(var.environments) : k => {
      wait_timer               = v.wait_timer
      can_admins_bypass        = v.can_admins_bypass
      prevent_self_review      = v.prevent_self_review
      reviewers                = try(v.reviewers, null)
      deployment_branch_policy = try(v.deployment_branch_policy, null)
      variables                = try(v.variables, null)
      secrets                  = try(v.secrets, null)
    }
  } : {}

  environment_reviewers_users = flatten([
    for k, v in local.environments : try(v.reviewers.users, [])
  ])

  environment_reviewers_teams = flatten([
    for k, v in local.environments : try(v.reviewers.teams, [])
  ])
}

data "github_user" "environment_reviewers" {
  for_each = toset(local.environment_reviewers_users)

  username = each.value
}

data "github_team" "environment_reviewers" {
  for_each = toset(local.environment_reviewers_teams)

  slug = each.value
}

resource "github_repository_environment" "default" {
  for_each = local.environments

  environment         = each.key
  repository          = join("", github_repository.default[*].name)
  prevent_self_review = each.value.prevent_self_review
  wait_timer          = each.value.wait_timer
  can_admins_bypass   = each.value.can_admins_bypass

  dynamic "reviewers" {
    for_each = each.value.reviewers != null ? [each.value.reviewers] : []
    content {
      users = [for user in reviewers.value.users : data.github_user.environment_reviewers[user].id]
      teams = [for team in reviewers.value.teams : data.github_team.environment_reviewers[team].id]
    }
  }
  dynamic "deployment_branch_policy" {
    for_each = local.environment_deployment_branch_policies[each.key]
    content {
      protected_branches     = deployment_branch_policy.value.protected_branches
      custom_branch_policies = !deployment_branch_policy.value.protected_branches
    }
  }

  depends_on = [
    github_repository_collaborators.default
  ]
}

locals {
  environment_variables = merge([
    for e, c in local.environments :
    c.variables != null ? { for k, v in c.variables : format("%s-%s", e, k) => { "environment" : e, "variable_name" : k, "variable_value" : v } } : {}
  ]...)

  environment_secrets = merge([
    for e, c in local.environments :
    c.secrets != null ? { for k, v in c.secrets : format("%s-%s", e, k) => { "environment" : e, "secret_name" : k, "secret_value" : v } } : {}
  ]...)

  environment_deployment_branch_policies = {
    for e, c in local.environments :
    e => c.deployment_branch_policy != null ? [c.deployment_branch_policy] : []
  }

  environment_custom_branch_policies = merge([
    for e, c in local.environment_deployment_branch_policies :
    try(c[0].custom_branches, null) != null ? { format("%s", e) : c[0].custom_branches } : {}
  ]...)

  environment_tag_patterns = merge([
    for e, c in local.environment_custom_branch_policies :
    try(c.tags, null) != null ? { for k, v in c.tags : format("%s-%s", e, k) => { "environment" : e, "pattern" : v } } : {}
  ]...)

  environment_branch_patterns = merge([
    for e, c in local.environment_custom_branch_policies :
    try(c.branches, null) != null ? { for k, v in c.branches : format("%s-%s", e, k) => { "environment" : e, "pattern" : v } } : {}
  ]...)
}

resource "github_repository_environment_deployment_policy" "tag_pattern" {
  for_each = local.environment_tag_patterns

  repository  = join("", github_repository.default[*].name)
  environment = github_repository_environment.default[each.value.environment].environment
  tag_pattern = each.value.pattern

  depends_on = [
    github_repository_environment.default
  ]
}

resource "github_repository_environment_deployment_policy" "branch_pattern" {
  for_each = local.environment_branch_patterns

  repository     = join("", github_repository.default[*].name)
  environment    = github_repository_environment.default[each.value.environment].environment
  branch_pattern = each.value.pattern

  depends_on = [
    github_repository_environment.default
  ]
}

resource "github_actions_environment_variable" "default" {
  for_each = local.environment_variables

  repository    = join("", github_repository.default[*].name)
  environment   = github_repository_environment.default[each.value.environment].environment
  variable_name = each.value.variable_name
  value         = each.value.variable_value
}

resource "github_actions_environment_secret" "default" {
  for_each = local.environment_secrets

  repository      = join("", github_repository.default[*].name)
  environment     = github_repository_environment.default[each.value.environment].environment
  secret_name     = each.value.secret_name
  plaintext_value = !startswith(each.value.secret_value, "nacl:") ? sensitive(each.value.secret_value) : null
  encrypted_value = startswith(each.value.secret_value, "nacl:") ? sensitive(trimprefix(each.value.secret_value, "nacl:")) : null
}

locals {
  variables   = module.this.enabled ? var.variables : {}
  secrets     = module.this.enabled ? { for k, v in nonsensitive(var.secrets) : k => sensitive(v) } : {}
  deploy_keys = module.this.enabled ? var.deploy_keys : {}
  webhooks    = module.this.enabled ? var.webhooks : {}
  labels      = module.this.enabled ? var.labels : {}
  rulesets    = module.this.enabled ? var.rulesets : {}
}

resource "github_actions_variable" "default" {
  for_each      = local.variables
  repository    = join("", github_repository.default[*].name)
  variable_name = each.key
  value         = each.value
}

resource "github_actions_secret" "default" {
  for_each        = local.secrets
  repository      = join("", github_repository.default[*].name)
  secret_name     = each.key
  plaintext_value = !startswith(each.value, "nacl:") ? each.value : null
  encrypted_value = startswith(each.value, "nacl:") ? trimprefix(each.value, "nacl:") : null
}

resource "github_repository_deploy_key" "default" {
  for_each   = local.deploy_keys
  repository = join("", github_repository.default[*].name)
  title      = each.value.title
  key        = each.value.key
  read_only  = each.value.read_only
}

resource "github_repository_webhook" "default" {
  for_each   = local.webhooks
  repository = join("", github_repository.default[*].name)

  active = each.value.active
  events = each.value.events
  configuration {
    url          = each.value.url
    content_type = each.value.content_type
    insecure_ssl = each.value.insecure_ssl
    secret       = each.value.secret
  }
}

resource "github_issue_label" "default" {
  for_each    = local.labels
  repository  = join("", github_repository.default[*].name)
  name        = each.key
  color       = trimprefix(each.value.color, "#")
  description = each.value.description
}

resource "github_repository_collaborators" "default" {
  count = module.this.enabled && length(var.teams) > 0 || length(var.users) > 0 ? 1 : 0

  repository = join("", github_repository.default[*].name)

  dynamic "team" {
    for_each = var.teams
    content {
      permission = team.value
      team_id    = team.key
    }
  }

  dynamic "user" {
    for_each = var.users
    content {
      permission = user.value
      username   = user.key
    }
  }
}

locals {
  organization_roles_map = {
    "maintain" = "2"
    "write"    = "4"
    "admin"    = "5"
  }

  ruleset_rules_teams = flatten([
    for e, c in local.rulesets :
    c.bypass_actors != null ? compact([for b in c.bypass_actors : b.actor_type == "Team" ? b.actor_id : null]) : []
  ])

  ruleset_conditions_refs_prefix = {
    "branch" = "refs/heads/"
    "tag"    = "refs/tags/"
  }
}

data "github_team" "ruleset_rules_teams" {
  for_each = toset(local.ruleset_rules_teams)

  slug = each.value
}

resource "github_repository_ruleset" "default" {
  for_each = local.rulesets

  repository = join("", github_repository.default[*].name)

  name        = each.value.name
  enforcement = each.value.enforcement
  target      = each.value.target

  conditions {
    ref_name {
      include = [
        for c in each.value.conditions.ref_name.include :
        startswith(c, local.ruleset_conditions_refs_prefix[each.value.target]) || c == "~DEFAULT_BRANCH" || c == "~ALL" ? c :
        format("%s%s", local.ruleset_conditions_refs_prefix[each.value.target], c)
      ]
      exclude = [
        for c in each.value.conditions.ref_name.exclude :
        startswith(c, local.ruleset_conditions_refs_prefix[each.value.target]) ? c :
        format("%s%s", local.ruleset_conditions_refs_prefix[each.value.target], c)
      ]
    }
  }

  dynamic "bypass_actors" {
    for_each = each.value.bypass_actors
    content {
      bypass_mode = bypass_actors.value.bypass_mode
      actor_id = (bypass_actors.value.actor_type == "OrganizationAdmin" ? "0" :
        bypass_actors.value.actor_type == "RepositoryRole" ? local.organization_roles_map[bypass_actors.value.actor_id] :
        bypass_actors.value.actor_type == "Team" ? data.github_team.ruleset_rules_teams[bypass_actors.value.actor_id].id :
      bypass_actors.value.actor_id)
      actor_type = bypass_actors.value.actor_type
    }
  }

  dynamic "rules" {
    for_each = each.value.rules != null ? [each.value.rules] : []
    content {
      creation         = rules.value.creation
      deletion         = rules.value.deletion
      non_fast_forward = rules.value.non_fast_forward

      dynamic "branch_name_pattern" {
        for_each = rules.value.branch_name_pattern != null ? [rules.value.branch_name_pattern] : []
        content {
          operator = branch_name_pattern.value.operator
          pattern  = branch_name_pattern.value.pattern
          negate   = branch_name_pattern.value.negate
          name     = branch_name_pattern.value.name
        }
      }
      dynamic "commit_author_email_pattern" {
        for_each = rules.value.commit_author_email_pattern != null ? [rules.value.commit_author_email_pattern] : []
        content {
          operator = commit_author_email_pattern.value.operator
          pattern  = commit_author_email_pattern.value.pattern
          negate   = commit_author_email_pattern.value.negate
          name     = commit_author_email_pattern.value.name
        }
      }
      dynamic "commit_message_pattern" {
        for_each = rules.value.commit_message_pattern != null ? [rules.value.commit_message_pattern] : []
        content {
          operator = commit_message_pattern.value.operator
          pattern  = commit_message_pattern.value.pattern
          negate   = commit_message_pattern.value.negate
          name     = commit_message_pattern.value.name
        }
      }
      dynamic "committer_email_pattern" {
        for_each = rules.value.committer_email_pattern != null ? [rules.value.committer_email_pattern] : []
        content {
          operator = committer_email_pattern.value.operator
          pattern  = committer_email_pattern.value.pattern
          negate   = committer_email_pattern.value.negate
          name     = committer_email_pattern.value.name
        }
      }

      dynamic "merge_queue" {
        for_each = rules.value.merge_queue != null ? [rules.value.merge_queue] : []
        content {
          check_response_timeout_minutes    = merge_queue.value.check_response_timeout_minutes
          grouping_strategy                 = merge_queue.value.grouping_strategy
          max_entries_to_build              = merge_queue.value.max_entries_to_build
          max_entries_to_merge              = merge_queue.value.max_entries_to_merge
          merge_method                      = merge_queue.value.merge_method
          min_entries_to_merge              = merge_queue.value.min_entries_to_merge
          min_entries_to_merge_wait_minutes = merge_queue.value.min_entries_to_merge_wait_minutes
        }
      }

      dynamic "pull_request" {
        for_each = rules.value.pull_request != null ? [rules.value.pull_request] : []
        content {
          dismiss_stale_reviews_on_push     = pull_request.value.dismiss_stale_reviews_on_push
          require_code_owner_review         = pull_request.value.require_code_owner_review
          require_last_push_approval        = pull_request.value.require_last_push_approval
          required_approving_review_count   = pull_request.value.required_approving_review_count
          required_review_thread_resolution = pull_request.value.required_review_thread_resolution
        }
      }

      dynamic "required_deployments" {
        for_each = rules.value.required_deployments != null ? [rules.value.required_deployments] : []
        content {
          required_deployment_environments = required_deployments.value.required_deployment_environments
        }
      }

      dynamic "required_status_checks" {
        for_each = rules.value.required_status_checks != null ? [rules.value.required_status_checks] : []
        content {
          dynamic "required_check" {
            for_each = required_status_checks.value.required_check
            content {
              context        = required_check.value.context
              integration_id = required_check.value.integration_id
            }
          }
          strict_required_status_checks_policy = required_status_checks.value.strict_required_status_checks_policy
          do_not_enforce_on_create             = required_status_checks.value.do_not_enforce_on_create
        }
      }

      dynamic "tag_name_pattern" {
        for_each = rules.value.tag_name_pattern != null ? [rules.value.tag_name_pattern] : []
        content {
          operator = tag_name_pattern.value.operator
          pattern  = tag_name_pattern.value.pattern
          negate   = tag_name_pattern.value.negate
          name     = tag_name_pattern.value.name
        }
      }

      # Unsupported due to drift. https://github.com/integrations/terraform-provider-github/pull/2701
      # dynamic "required_code_scanning" {
      #   for_each = rules.value.required_code_scanning != null ? [rules.value.required_code_scanning] : []
      #   content {
      #     dynamic "required_code_scanning_tool" {
      #       for_each = required_code_scanning.value.required_code_scanning_tool
      #       content {
      #         alerts_threshold          = required_code_scanning_tool.value.alerts_threshold
      #         security_alerts_threshold = required_code_scanning_tool.value.security_alerts_threshold
      #         tool                      = required_code_scanning_tool.value.tool
      #       }
      #     }
      #   }
      # }
    }
  }
  depends_on = [
    github_repository_environment.default
  ]
}
