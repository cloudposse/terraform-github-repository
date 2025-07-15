module "example" {
  source  = "../.."
  context = module.this.context

  repository          = var.repository
  archive_on_destroy  = var.archive_on_destroy
  autolink_references = var.autolink_references

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

