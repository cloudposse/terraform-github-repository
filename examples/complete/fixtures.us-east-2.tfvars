owner = "cloudposse-tests"

description                             = "Terraform acceptance tests"
visibility                              = "public"
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
  secret_scanning                 = true
  secret_scanning_push_protection = true
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
