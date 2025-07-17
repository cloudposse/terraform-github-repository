output "full_name" {
  description = "Full name of the created repository"
  value       = join("", github_repository.default[*].full_name)
}

output "html_url" {
  description = "HTML URL of the created repository"
  value       = join("", github_repository.default[*].html_url)
}

output "ssh_clone_url" {
  description = "SSH clone URL of the created repository"
  value       = join("", github_repository.default[*].ssh_clone_url)
}

output "http_clone_url" {
  description = "SSH clone URL of the created repository"
  value       = join("", github_repository.default[*].http_clone_url)
}

output "git_clone_url" {
  description = "Git clone URL of the created repository"
  value       = join("", github_repository.default[*].git_clone_url)
}

output "svn_url" {
  description = "SVN URL of the created repository"
  value       = join("", github_repository.default[*].svn_url)
}

output "node_id" {
  description = "Node ID of the created repository"
  value       = join("", github_repository.default[*].node_id)
}

output "repo_id" {
  description = "Repository ID of the created repository"
  value       = join("", github_repository.default[*].repo_id)
}

output "primary_language" {
  description = "Primary language of the created repository"
  value       = join("", github_repository.default[*].primary_language)
}

output "webhooks_urls" {
  description = "Webhooks URLs"
  value       = { for k, v in github_repository_webhook.default : k => v.url }
}

output "collaborators_invitation_ids" {
  description = "Collaborators invitation IDs"
  value       = module.this.enabled ? github_repository_collaborators.default[*].invitation_ids : []
}

output "rulesets_etags" {
  description = "Rulesets etags"
  value       = { for k, v in github_repository_ruleset.default : k => v.etag }
}

output "rulesets_node_ids" {
  description = "Rulesets node IDs"
  value       = { for k, v in github_repository_ruleset.default : k => v.node_id }
}

output "rulesets_rules_ids" {
  description = "Rulesets rules IDs"
  value       = { for k, v in github_repository_ruleset.default : k => format("%d", v.ruleset_id) }
}
