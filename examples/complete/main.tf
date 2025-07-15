module "example" {
  source  = "../.."
  context = module.this.context

  description                             = var.description
  visibility                              = var.visibility
  homepage_url                            = var.homepage_url
  archived                                = var.archived
  has_issues                              = var.has_issues
  has_projects                            = var.has_projects
  has_discussions                         = var.has_discussions
  has_wiki                                = var.has_wiki
  archive_on_destroy                      = var.archive_on_destroy
  autolink_references                     = var.autolink_references
  default_branch                          = var.default_branch
  web_commit_signoff_required             = var.web_commit_signoff_required
  topics                                  = var.topics
  license_template                        = var.license_template
  gitignore_template                      = var.gitignore_template
  auto_init                               = var.auto_init
  ignore_vulnerability_alerts_during_read = var.ignore_vulnerability_alerts_during_read
  enable_vulnerability_alerts             = var.enable_vulnerability_alerts
  allow_update_branch                     = var.allow_update_branch
  security_and_analysis                   = var.security_and_analysis
  allow_squash_merge                      = var.allow_squash_merge
  squash_merge_commit_title               = var.squash_merge_commit_title
  squash_merge_commit_message             = var.squash_merge_commit_message
  allow_merge_commit                      = var.allow_merge_commit
  merge_commit_title                      = var.merge_commit_title
  merge_commit_message                    = var.merge_commit_message
  allow_rebase_merge                      = var.allow_rebase_merge
  delete_branch_on_merge                  = var.delete_branch_on_merge
  is_template                             = var.is_template
  has_downloads                           = var.has_downloads
  allow_auto_merge                        = var.allow_auto_merge

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

