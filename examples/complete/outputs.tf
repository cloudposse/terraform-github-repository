output "full_name" {
  description = "Full name of the created repository"
  value       = module.example.full_name
}

output "html_url" {
  description = "HTML URL of the created repository"
  value       = module.example.html_url
}

output "ssh_clone_url" {
  description = "SSH clone URL of the created repository"
  value       = module.example.ssh_clone_url
}

output "http_clone_url" {
  description = "SSH clone URL of the created repository"
  value       = module.example.http_clone_url
}

output "git_clone_url" {
  description = "Git clone URL of the created repository"
  value       = module.example.git_clone_url
}

output "svn_url" {
  description = "SVN URL of the created repository"
  value       = module.example.svn_url
}

output "node_id" {
  description = "Node ID of the created repository"
  value       = module.example.node_id
}

output "repo_id" {
  description = "Repository ID of the created repository"
  value       = module.example.repo_id
}

output "primary_language" {
  description = "Primary language of the created repository"
  value       = module.example.primary_language
}

output "autolink_references_etags" {
  description = "Autolink references etags"
  value       = module.example.autolink_references_etags
}

output "webhooks_urls" {
  description = "Webhooks URLs"
  value       = module.example.webhooks_urls
}

output "collaborators_invitation_ids" {
  description = "Collaborators invitation IDs"
  value       = module.example.collaborators_invitation_ids
}

output "rulesets_etags" {
  description = "Rulesets etags"
  value       = module.example.rulesets_etags
}

output "rulesets_node_ids" {
  description = "Rulesets node IDs"
  value       = module.example.rulesets_node_ids
}

output "rulesets_rules_ids" {
  description = "Rulesets rules IDs"
  value       = module.example.rulesets_rules_ids
}
