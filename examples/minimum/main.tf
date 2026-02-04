module "example" {
  source  = "../.."
  context = module.this.context

  name = module.this.id

  template = var.template

  description = var.description
  visibility  = var.visibility

  homepage_url = var.homepage_url
  topics       = var.topics

  archived           = var.archived
  archive_on_destroy = var.archive_on_destroy

  is_template = var.is_template

  has_discussions = var.has_discussions
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

  ignore_vulnerability_alerts_during_read = var.ignore_vulnerability_alerts_during_read

  autolink_references         = var.autolink_references
  default_branch              = var.default_branch
  enable_vulnerability_alerts = var.enable_vulnerability_alerts
  security_and_analysis       = var.security_and_analysis

  custom_properties = var.custom_properties
  environments      = var.environments

  variables   = var.variables
  secrets     = var.secrets
  deploy_keys = var.deploy_keys
  webhooks    = var.webhooks
  labels      = var.labels
  teams       = var.teams
  users       = var.users
  rulesets    = var.rulesets
}
