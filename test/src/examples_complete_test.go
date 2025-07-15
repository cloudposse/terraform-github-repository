package test

import (
  "os"
  "strings"
  "testing"
  "context"
  "fmt"
  "time"

  "github.com/gruntwork-io/terratest/modules/random"
  "github.com/gruntwork-io/terratest/modules/terraform"
  testStructure "github.com/gruntwork-io/terratest/modules/test-structure"
  "github.com/stretchr/testify/assert"
  "github.com/google/go-github/v73/github"
)

const owner = "cloudposse-tests"

func cleanup(t *testing.T, terraformOptions *terraform.Options, tempTestFolder string) {
  terraform.Destroy(t, terraformOptions)
  os.RemoveAll(tempTestFolder)
}

// Test the Terraform module in examples/complete using Terratest.
func TestExamplesComplete(t *testing.T) {
  t.Parallel()
  randID := strings.ToLower(random.UniqueId())

  rootFolder := "../../"
  terraformFolderRelativeToRoot := "examples/complete"
  varFiles := []string{"fixtures.us-east-2.tfvars"}

  tempTestFolder := testStructure.CopyTerraformFolderToTemp(t, rootFolder, terraformFolderRelativeToRoot)

  repositoryName := fmt.Sprintf("terraform-github-repository-test-%s", randID)

  deployKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCpXx34NELRFyPu0tAtd+ic1uETwoPbTZd7doqCvNCPyV5SxE8p5IRNoLJvzQkx8aRHlzp1UEui4U7BfuMD3gxs2sWX/NVZ1qqRzl+6KgRCILUnprxmC6osoP+kkk3ZaW62gFtSGNOux21Cu6KP2cOdumYgRLvBsyns/D1vf2TLOQ=="

  terraformOptions := &terraform.Options{
    // The path to where our Terraform code is located
    TerraformDir: tempTestFolder,
    Upgrade:      true,
    // Variables to pass to our Terraform code using -var-file options
    VarFiles: varFiles,
    Vars: map[string]interface{}{
      "enabled":    true,
      "repository": map[string]interface{}{
        "name": repositoryName,
        "description": "Terraform acceptance tests",
        "visibility": "public",
        "homepage_url": "http://example.com/",
        "archived": false,
        "has_issues": true,
        "has_discussions": true,
        "has_projects": true,
        "has_wiki": true,
        "has_downloads": true,
        "is_template": true,
        "allow_merge_commit": true,
        "merge_commit_title": "MERGE_MESSAGE",
        "merge_commit_message": "PR_TITLE",
        "allow_squash_merge": true,
        "squash_merge_commit_title": "COMMIT_OR_PR_TITLE",
        "squash_merge_commit_message": "COMMIT_MESSAGES",
        "web_commit_signoff_required": true,
        "allow_rebase_merge": true,
        "allow_auto_merge": true,
        "delete_branch_on_merge": true,
        "default_branch": "main",
        "gitignore_template": "TeX",
        "license_template": "GPL-3.0",
        "auto_init": true,
        "topics": []string{"terraform", "github", "test"},
        "ignore_vulnerability_alerts_during_read": true,
        "allow_update_branch": true,
        "security_and_analysis": map[string]interface{}{
          "advanced_security": false,
          "secret_scanning": true,
          "secret_scanning_push_protection": true,
        },
      },
      "archive_on_destroy": false,
      "autolink_references": map[string]interface{}{
        "jira": map[string]interface{}{
          "key_prefix": "JIRA-",
          "target_url_template": "https://jira.example.com/browse/<num>",
        },
      },
      "custom_properties": map[string]interface{}{
        "test-boolean": map[string]interface{}{
          "boolean": true,
        },
        "test-single-select": map[string]interface{}{
          "single_select": "Value 1",
        },
        "test-multi-select": map[string]interface{}{
          "multi_select": []string{"Value 2", "Value 3"},
        },
        "test-string": map[string]interface{}{
          "string": "Test text value",
        },
      },
      "environments": map[string]interface{}{
        "staging": map[string]interface{}{
          "wait_timer": 1,
          "can_admins_bypass": true,
          "prevent_self_review": true,
          "reviewers": map[string]interface{}{
            // Teams are not supported yet
            //"teams": []string{"test-team"},
            "users": []string{"cloudposse-test-bot"},
          },
          "deployment_branch_policy": map[string]interface{}{
            "protected_branches": true,
            "custom_branches": nil,
          },
          "variables": map[string]interface{}{
            "test_variable": "test-value",
            "test_variable_2": "test-value-2",
          },
        },
        "development": map[string]interface{}{
          "wait_timer": 5,
          "can_admins_bypass": false,
          "prevent_self_review": false,
          "variables": map[string]interface{}{},
        },
        "production": map[string]interface{}{
          "wait_timer": 10,
          "can_admins_bypass": false,
          "prevent_self_review": false,
          "deployment_branch_policy": map[string]interface{}{
            "protected_branches": false,
            "custom_branches": map[string]interface{}{
              "branches": []string{"main"},
              "tags": []string{"v1.0.0"},
            },
          },
          "secrets": map[string]interface{}{
            "test_secret": "test-value",
            "test_secret_2": "nacl:dGVzdC12YWx1ZS0yCg==",
          },
        },
      },
      "variables": map[string]interface{}{
        "test_variable": "test-value",
        "test_variable_2": "test-value-2",
      },
      "secrets": map[string]interface{}{
        "test_secret": "test-value",
        "test_secret_2": "nacl:dGVzdC12YWx1ZS0yCg==",
      },
      "deploy_keys": map[string]interface{}{
        "cicd-key": map[string]interface{}{
          "title": "CI/CD Deploy Key",
          "key": deployKey,
          "read_only": true,
        },
      },
      "webhooks": map[string]interface{}{
        "notify-on-push": map[string]interface{}{
          "active": true,
          "url": "https://hooks.example.com/github",
          "events": []string{"push", "pull_request"},
          "content_type": "json",
          "insecure_ssl": false,
          "secret": "test-secret",
        },
      },
      "labels": map[string]interface{}{
        "bug2": map[string]interface{}{
          "color": "#a73a4a",
          "description": "🐛 An issue with the system",
        },
        "feature2": map[string]interface{}{
          "color": "#336699",
          "description": "New functionality",
        },
      },
      "teams": map[string]interface{}{
        "admin": "admin",
        "test-team": "push",
      },
      "users": map[string]interface{}{
        "cloudposse-test-bot": "admin",
      },
      "rulesets": map[string]interface{}{
        "default": map[string]interface{}{
          "name": "Default protection",
          "enforcement": "active",
          "target": "branch",
          "conditions": map[string]interface{}{
            "ref_name": map[string]interface{}{
              "include": []string{
                "~ALL",
              },
              "exclude": []string{
                "refs/heads/releases",
                "main",
              },
            },
          },
          "bypass_actors": []map[string]interface{}{
            {
              "bypass_mode": "always",
              "actor_type": "OrganizationAdmin",
            },
            {
              "bypass_mode": "pull_request",
              "actor_type": "RepositoryRole",
              "actor_id": "maintain",
            },
            {
              "bypass_mode": "pull_request",
              "actor_type": "RepositoryRole",
              "actor_id": "write",
            },
            {
              "bypass_mode": "pull_request",
              "actor_type": "RepositoryRole",
              "actor_id": "admin",
            },
            {
              "bypass_mode": "always",
              "actor_type": "Team",
              "actor_id": "test-team",
            },
            {
              "bypass_mode": "always",
              "actor_type": "Integration",
              "actor_id": "1199797",
            },
          },
          "rules": map[string]interface{}{
            "branch_name_pattern": map[string]interface{}{
              "operator": "starts_with",
              "pattern": "release",
              "name": "Release branch",
              "negate": false,
            },
            "commit_author_email_pattern": map[string]interface{}{
              "operator": "contains",
              "pattern": "gmail.com",
              "name": "Gmail email",
              "negate": true,
            },
            "commit_message_pattern": map[string]interface{}{
              "operator": "ends_with",
              "pattern": "test",
              "name": "Test message",
              "negate": false,
            },
            "committer_email_pattern": map[string]interface{}{
              "operator": "contains",
              "pattern": "test@example.com",
              "name": "Test committer email",
              "negate": false,
            },
            "creation": true,
            "deletion": false,
            "non_fast_forward": true,
            // "merge_queue": map[string]interface{}{
            //   "check_response_timeout_minutes": 10,
            //   "grouping_strategy": "ALLGREEN",
            //   "max_entries_to_build": 10,
            //   "max_entries_to_merge": 15,
            //   "merge_method": "MERGE",
            //   "min_entries_to_merge": 1,
            //   "min_entries_to_merge_wait_minutes": 10,
            // },
            "pull_request": map[string]interface{}{
              "dismiss_stale_reviews_on_push": true,
              "require_code_owner_review": true,
              "require_last_push_approval": true,
              "required_approving_review_count": 1,
              "required_review_thread_resolution": true,
            },
            "required_deployments": map[string]interface{}{
              "required_deployment_environments": []string{
                "staging",
                "production",
              },
            },
            "required_status_checks": map[string]interface{}{
              "required_check": []map[string]interface{}{
                {
                  "context": "test",
                },
                {
                  "context": "test2",
                  "integration_id": "1199797",
                },
              },
              "strict_required_status_checks_policy": true,
              "do_not_enforce_on_create": true,
            },
            // "tag_name_pattern": map[string]interface{}{
            //   "operator": "regexp",
            //   "pattern": "^v\\\\d+\\\\.\\\\d+\\\\.\\\\d+$",
            //   "name": "Tag name",
            //   "negate": false,
            // },
            // "required_code_scanning": map[string]interface{}{
            //   "required_code_scanning_tool": []map[string]interface{}{
            //     {
            //       "alerts_threshold": "errors",
            //       "security_alerts_threshold": "high_or_higher",
            //       "tool": "CodeQL",
            //     },
            //   },
            // },
          },
        },
      },
    },
  }


  // At the end of the test, run `terraform destroy` to clean up any resources that were created
  defer cleanup(t, terraformOptions, tempTestFolder)

  // This will run `terraform init` and `terraform apply` and fail the test if there are any errors
  terraform.InitAndApply(t, terraformOptions)

  time.Sleep(120 * time.Second)

  token := os.Getenv("GITHUB_TOKEN")

  client := github.NewClient(nil).WithAuthToken(token)

  repo, _, err := client.Repositories.Get(context.Background(), owner, repositoryName)
  assert.NoError(t, err)


  assert.Equal(t, repositoryName, repo.GetName())
  assert.Equal(t, "Terraform acceptance tests", repo.GetDescription())
  assert.Equal(t, "http://example.com/", repo.GetHomepage())
  assert.Equal(t, false, repo.GetPrivate())
  assert.Equal(t, "public", repo.GetVisibility())

  // Additional assertions for repository attributes
  assert.Equal(t, false, repo.GetArchived())
  assert.Equal(t, true, repo.GetHasIssues())
  assert.Equal(t, true, repo.GetHasProjects())
  assert.Equal(t, true, repo.GetHasDiscussions())
  assert.Equal(t, true, repo.GetHasWiki())
  assert.Equal(t, true, repo.GetHasDownloads())
  assert.Equal(t, true, repo.GetIsTemplate())
  assert.Equal(t, true, repo.GetAllowSquashMerge())
  assert.Equal(t, "COMMIT_OR_PR_TITLE", repo.GetSquashMergeCommitTitle())
  assert.Equal(t, "COMMIT_MESSAGES", repo.GetSquashMergeCommitMessage())
  assert.Equal(t, true, repo.GetAllowMergeCommit())
  assert.Equal(t, "MERGE_MESSAGE", repo.GetMergeCommitTitle())
  assert.Equal(t, "PR_TITLE", repo.GetMergeCommitMessage())
  assert.Equal(t, true, repo.GetAllowRebaseMerge())
  assert.Equal(t, true, repo.GetWebCommitSignoffRequired())
  assert.Equal(t, true, repo.GetDeleteBranchOnMerge())
  assert.Equal(t, "main", repo.GetDefaultBranch())
  assert.Equal(t, true, repo.GetAllowUpdateBranch())

  // For public repositories, advanced security cannot be changed
  assert.Equal(t, "", repo.GetSecurityAndAnalysis().GetAdvancedSecurity().GetStatus())
  assert.Equal(t, "enabled", repo.GetSecurityAndAnalysis().GetSecretScanning().GetStatus())
  assert.Equal(t, "enabled", repo.GetSecurityAndAnalysis().GetSecretScanningPushProtection().GetStatus())

  // Check if the repository was auto-initialized
  commits, _, err := client.Repositories.ListCommits(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.Equal(t, 1, len(commits), "Expected only one commit in the repository history")


  topics, _, err := client.Repositories.ListAllTopics(context.Background(), owner, repositoryName)
  assert.NoError(t, err)
  expectedTopics := []string{"terraform", "github", "test"}
  // The default in variables.tf is an empty list, but you may want to update this if your test sets topics
  assert.ElementsMatch(t, expectedTopics, topics)

  autolinkReferences, _, err := client.Repositories.ListAutolinks(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.Equal(t, 1, len(autolinkReferences))
  assert.Equal(t, "JIRA-", autolinkReferences[0].GetKeyPrefix())
  assert.Equal(t, "https://jira.example.com/browse/<num>", autolinkReferences[0].GetURLTemplate())

  repoCustomProperties := repo.GetCustomProperties()
  assert.Equal(t, 4, len(repoCustomProperties))
  assert.Equal(t, "true", repoCustomProperties["test-boolean"])
  assert.Equal(t, "Value 1", repoCustomProperties["test-single-select"])
  assert.ElementsMatch(t, []string{"Value 2", "Value 3"}, repoCustomProperties["test-multi-select"])
  assert.Equal(t, "Test text value", repoCustomProperties["test-string"])

  // Get repository environments and add assertions

  envs, _, err := client.Repositories.ListEnvironments(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, envs)
  assert.Equal(t, 3, len(envs.Environments), "Expected 2 environments")

  env, _, err := client.Repositories.GetEnvironment(context.Background(), owner, repositoryName, "staging")
  assert.NoError(t, err)
  assert.NotNil(t, env)

  assert.Equal(t, true, env.GetCanAdminsBypass(), "Expected can_admins_bypass to be true for staging")
  assert.Equal(t, 3, len(env.ProtectionRules), "Expected 3 reviewers for staging")
  assert.Equal(t, "required_reviewers", env.ProtectionRules[0].GetType(), "Expected required_reviewers to be true for staging")
  assert.Equal(t, "wait_timer", env.ProtectionRules[1].GetType(), "Expected wait_timer to be true for staging")
  assert.Equal(t, "branch_policy", env.ProtectionRules[2].GetType(), "Expected branch_policy to be true for staging")

  assert.Equal(t, 1, len(env.ProtectionRules[0].Reviewers), "Expected 1 reviewer for staging")
  assert.Equal(t, "User", env.ProtectionRules[0].Reviewers[0].GetType(), "Expected reviewer to be cloudposse-test-bot for staging")
  assert.Equal(t, true, env.ProtectionRules[0].GetPreventSelfReview(), "Expected prevent_self_review to be true for staging")

  reviewerUser := env.ProtectionRules[0].Reviewers[0].Reviewer
  githubUser, ok := reviewerUser.(*github.User)
  assert.True(t, ok, "Expected reviewerUser to be of type *github.User")
  assert.Equal(t, "cloudposse-test-bot", githubUser.GetLogin(), "Expected reviewer to be cloudposse-test-bot for staging")

  assert.Equal(t, 1, env.ProtectionRules[1].GetWaitTimer(), "Expected wait_timer to be 1 for staging")

  deploymentBranchPolicies, _, err := client.Repositories.ListDeploymentBranchPolicies(context.Background(), owner, repositoryName, "staging")
	assert.Error(t, err)

  env, _, err = client.Repositories.GetEnvironment(context.Background(), owner, repositoryName, "development")
  assert.NoError(t, err)
  assert.NotNil(t, env)

  assert.Equal(t, false, env.GetCanAdminsBypass(), "Expected can_admins_bypass to be false for development")
  assert.Equal(t, 1, len(env.ProtectionRules), "Expected 2 reviewers for development")
  assert.Equal(t, "wait_timer", env.ProtectionRules[0].GetType(), "Expected wait_timer to be true for development")
  assert.Equal(t, 5, env.ProtectionRules[0].GetWaitTimer(), "Expected wait_timer to be 5 for development")

  deploymentBranchPolicies, _, err = client.Repositories.ListDeploymentBranchPolicies(context.Background(), owner, repositoryName, "development")
	assert.Error(t, err)

  env, _, err = client.Repositories.GetEnvironment(context.Background(), owner, repositoryName, "production")
  assert.NoError(t, err)
  assert.NotNil(t, env)

  assert.Equal(t, false, env.GetCanAdminsBypass(), "Expected can_admins_bypass to be false for production")
  assert.Equal(t, 2, len(env.ProtectionRules), "Expected 2 reviewers for production")
  assert.Equal(t, "wait_timer", env.ProtectionRules[0].GetType(), "Expected wait_timer to be true for production")
  assert.Equal(t, 10, env.ProtectionRules[0].GetWaitTimer(), "Expected wait_timer to be 10 for production")

  assert.Equal(t, "branch_policy", env.ProtectionRules[1].GetType(), "Expected branch_policy to be true for production")


	deploymentBranchPolicies, _, err = client.Repositories.ListDeploymentBranchPolicies(context.Background(), owner, repositoryName, "production")
	assert.NoError(t, err)
	assert.NotNil(t, deploymentBranchPolicies)
	assert.Equal(t, len(deploymentBranchPolicies.BranchPolicies), 2, "Expected 2 deployment branch policies for production")

	branchPolicy, _, err := client.Repositories.GetDeploymentBranchPolicy(context.Background(), owner, repositoryName, "production", deploymentBranchPolicies.BranchPolicies[0].GetID())
  assert.NoError(t, err)
  assert.NotNil(t, branchPolicy)
  assert.Equal(t, "branch", branchPolicy.GetType(), "Expected protected_branches to be true for production")
  assert.Equal(t, "main", branchPolicy.GetName(), "Expected custom_branches to be main for production")

	branchPolicy, _, err = client.Repositories.GetDeploymentBranchPolicy(context.Background(), owner, repositoryName, "production", deploymentBranchPolicies.BranchPolicies[1].GetID())
  assert.NoError(t, err)
  assert.NotNil(t, branchPolicy)
  assert.Equal(t, "tag", branchPolicy.GetType(), "Expected protected_branches to be true for production")
  assert.Equal(t, "v1.0.0", branchPolicy.GetName(), "Expected custom_branches to be main for production")

  envVars, _, err := client.Actions.ListEnvVariables(context.Background(), owner, repositoryName, "staging", nil)
  assert.NoError(t, err)
  assert.NotNil(t, envVars)
  assert.Equal(t, 2, len(envVars.Variables), "Expected 2 environment variables for staging")

  assert.Equal(t, "TEST_VARIABLE", envVars.Variables[0].Name, "Expected test-variable to be in staging environment")
  assert.Equal(t, "test-value", envVars.Variables[0].Value, "Expected test-value to be in staging environment")
  assert.Equal(t, "TEST_VARIABLE_2", envVars.Variables[1].Name, "Expected test-variable-2 to be in staging environment")
  assert.Equal(t, "test-value-2", envVars.Variables[1].Value, "Expected test-value-2 to be in staging environment")

  envSecrets, _, err := client.Actions.ListEnvSecrets(context.Background(), int(repo.GetID()), "production", nil)
  assert.NoError(t, err)
  assert.NotNil(t, envSecrets)
  assert.Equal(t, 2, len(envSecrets.Secrets), "Expected 2 environment variables for production")

  assert.Equal(t, "TEST_SECRET", envSecrets.Secrets[0].Name, "Expected test-variable to be in staging environment")
  assert.Equal(t, "TEST_SECRET_2", envSecrets.Secrets[1].Name, "Expected test-variable-2 to be in staging environment")


  vars, _, err := client.Actions.ListRepoVariables(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, vars)
  assert.Equal(t, 2, len(vars.Variables), "Expected 2 environment variables for production")
  assert.Equal(t, "TEST_VARIABLE", vars.Variables[0].Name, "Expected test-variable to be in production environment")
  assert.Equal(t, "test-value", vars.Variables[0].Value, "Expected test-value to be in production environment")
  assert.Equal(t, "TEST_VARIABLE_2", vars.Variables[1].Name, "Expected test-variable-2 to be in production environment")
  assert.Equal(t, "test-value-2", vars.Variables[1].Value, "Expected test-value-2 to be in production environment")

  secrets, _, err := client.Actions.ListRepoSecrets(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, secrets)
  assert.Equal(t, 2, len(secrets.Secrets), "Expected 2 environment variables for production")
  assert.Equal(t, "TEST_SECRET", secrets.Secrets[0].Name, "Expected test-variable to be in production environment")
  assert.Equal(t, "TEST_SECRET_2", secrets.Secrets[1].Name, "Expected test-variable-2 to be in production environment")


  deployKeys, _, err := client.Repositories.ListKeys(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, deployKeys)
  assert.Equal(t, 1, len(deployKeys), "Expected 1 deploy key for production")
  assert.Equal(t, "CI/CD Deploy Key", deployKeys[0].GetTitle(), "Expected CI/CD Deploy Key to be in production")


  webhooks, _, err := client.Repositories.ListHooks(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, webhooks)
  assert.Equal(t, 1, len(webhooks), "Expected 1 webhook for production")

  webhook := webhooks[0]
  assert.Equal(t, "Repository", webhook.GetType(), "Expected webhook type to be 'web'")
  assert.Equal(t, "web", webhook.GetName(), "Expected webhook name to be 'notify-on-push'")
  assert.NotNil(t, webhook.GetConfig(), "Expected webhook config to not be nil")
  assert.Equal(t, "https://hooks.example.com/github", webhook.GetConfig().GetURL(), "Expected webhook url to match")
  assert.Equal(t, "json", webhook.GetConfig().GetContentType(), "Expected webhook content_type to be 'json'")
  assert.Equal(t, "0", webhook.GetConfig().GetInsecureSSL(), "Expected webhook insecure_ssl to be '0'")
  assert.Equal(t, "********", webhook.GetConfig().GetSecret(), "Expected webhook secret to match")
  assert.ElementsMatch(t, []string{"push", "pull_request"}, webhook.Events, "Expected webhook events to match")
  assert.Equal(t, true, webhook.GetActive(), "Expected webhook to be active")

  labels, _, err := client.Issues.ListLabels(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, labels)

  // Check the description and color for labels "bug2" and "feature2"
  var bug2Label, feature2Label *github.Label
  for _, label := range labels {
    switch label.GetName() {
    case "bug2":
      bug2Label = label
    case "feature2":
      feature2Label = label
    }
  }
  assert.NotNil(t, bug2Label, "Expected to find label 'bug2'")
  assert.NotNil(t, feature2Label, "Expected to find label 'feature2'")

  assert.Equal(t, "a73a4a", bug2Label.GetColor(), "Expected bug2 label color to be '#a73a4a'")
  assert.Equal(t, "🐛 An issue with the system", bug2Label.GetDescription(), "Expected bug2 label description to be '🐛 An issue with the system'")

  assert.Equal(t, "336699", feature2Label.GetColor(), "Expected feature2 label color to be '#336699'")
  assert.Equal(t, "New functionality", feature2Label.GetDescription(), "Expected feature2 label description to be 'New functionality'")

  teams, _, err := client.Repositories.ListTeams(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, teams)
  assert.Equal(t, 2, len(teams), "Expected 2 teams for production")
  assert.Equal(t, "admin", teams[0].GetName(), "Expected test-team to be in production")
  assert.Equal(t, "admin", teams[0].GetPermission(), "Expected test-team to have push permission")
  assert.Equal(t, "test-team", teams[1].GetName(), "Expected test-team to be in production")
  assert.Equal(t, "push", teams[1].GetPermission(), "Expected test-team to have push permission")

  test_team := teams[1]


  users, _, err := client.Repositories.ListCollaborators(context.Background(), owner, repositoryName, &github.ListCollaboratorsOptions{Permission: "admin"})
  assert.NoError(t, err)
  assert.NotNil(t, users)
  assert.GreaterOrEqual(t, len(users), 1, "Expected 2 teams for production")

  var foundUser bool
  for _, user := range users {
    if user.GetLogin() == "cloudposse-test-bot" {
      foundUser = true
      break
    }
  }
  assert.True(t, foundUser, "Expected users to contain 'cloudposse-test-bot'")


  rulesets, _, err := client.Repositories.GetAllRulesets(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, rulesets)
  assert.Equal(t, 1, len(rulesets), "Expected 1 ruleset for production")

  ruleset, _, err := client.Repositories.GetRuleset(context.Background(), owner, repositoryName, rulesets[0].GetID(), true)
  assert.NoError(t, err)
  assert.NotNil(t, ruleset)

  assert.Equal(t, "Default protection", ruleset.Name, "Expected default protection to be in production")
  assert.EqualValues(t, "active", ruleset.Enforcement, "Expected default protection to be active")
  assert.EqualValues(t, "Repository", *ruleset.SourceType, "Expected default protection to be on branch")
  assert.EqualValues(t, "branch", *ruleset.Target, "Expected default protection to be on branch")
  assert.EqualValues(t, fmt.Sprintf("%s/%s", owner, repositoryName), ruleset.Source, "Expected default protection to be on branch")
  assert.EqualValues(t, "~ALL", ruleset.GetConditions().RefName.Include[0], "Expected default protection to be on branch")
  assert.EqualValues(t, "refs/heads/releases", ruleset.GetConditions().RefName.Exclude[0], "Expected default protection to be on branch")
  assert.EqualValues(t, "refs/heads/main", ruleset.GetConditions().RefName.Exclude[1], "Expected default protection to be on branch")

  assert.EqualValues(t, 6, len(ruleset.BypassActors), "Expected default protection to be on branch")
  assert.EqualValues(t, "always", *ruleset.BypassActors[0].GetBypassMode(), "Expected default protection to be on branch")
  assert.EqualValues(t, "OrganizationAdmin", *ruleset.BypassActors[0].GetActorType(), "Expected default protection to be on branch")
  assert.Equal(t, int64(0), ruleset.BypassActors[0].GetActorID(), "Expected default protection to be on branch")

  assert.EqualValues(t, "pull_request", *ruleset.BypassActors[1].GetBypassMode(), "Expected default protection to be on branch")
  assert.EqualValues(t, "RepositoryRole", *ruleset.BypassActors[1].GetActorType(), "Expected default protection to be on branch")
  assert.Equal(t, int64(2), ruleset.BypassActors[1].GetActorID(), "Expected default protection to be on branch")

  assert.EqualValues(t, "pull_request", *ruleset.BypassActors[2].GetBypassMode(), "Expected default protection to be on branch")
  assert.EqualValues(t, "RepositoryRole", *ruleset.BypassActors[2].GetActorType(), "Expected default protection to be on branch")
  assert.Equal(t, int64(4), ruleset.BypassActors[2].GetActorID(), "Expected default protection to be on branch")

  assert.EqualValues(t, "pull_request", *ruleset.BypassActors[3].GetBypassMode(), "Expected default protection to be on branch")
  assert.EqualValues(t, "RepositoryRole", *ruleset.BypassActors[3].GetActorType(), "Expected default protection to be on branch")
  assert.Equal(t, int64(5), ruleset.BypassActors[3].GetActorID(), "Expected default protection to be on branch")

  assert.EqualValues(t, "always", *ruleset.BypassActors[4].GetBypassMode(), "Expected default protection to be on branch")
  assert.EqualValues(t, "Integration", *ruleset.BypassActors[4].GetActorType(), "Expected default protection to be on branch")
  assert.Equal(t, int64(1199797), ruleset.BypassActors[4].GetActorID(), "Expected default protection to be on branch")

  assert.EqualValues(t, "always", *ruleset.BypassActors[5].GetBypassMode(), "Expected default protection to be on branch")
  assert.EqualValues(t, "Team", *ruleset.BypassActors[5].GetActorType(), "Expected default protection to be on branch")
  assert.Equal(t, test_team.GetID(), ruleset.BypassActors[5].GetActorID(), "Expected default protection to be on branch")

  assert.EqualValues(t, "starts_with", ruleset.GetRules().GetBranchNamePattern().Operator, "Expected default protection to be on branch")
  assert.EqualValues(t, "release", ruleset.GetRules().GetBranchNamePattern().Pattern, "Expected default protection to be on branch")
  assert.EqualValues(t, "Release branch", ruleset.GetRules().GetBranchNamePattern().GetName(), "Expected default protection to be on branch")
  assert.EqualValues(t, false, ruleset.GetRules().GetBranchNamePattern().GetNegate(), "Expected default protection to be on branch")

  assert.EqualValues(t, "contains", ruleset.GetRules().GetCommitAuthorEmailPattern().Operator, "Expected default protection to be on branch")
  assert.EqualValues(t, "gmail.com", ruleset.GetRules().GetCommitAuthorEmailPattern().Pattern, "Expected default protection to be on branch")
  assert.EqualValues(t, "Gmail email", ruleset.GetRules().GetCommitAuthorEmailPattern().GetName(), "Expected default protection to be on branch")
  assert.EqualValues(t, true, ruleset.GetRules().GetCommitAuthorEmailPattern().GetNegate(), "Expected default protection to be on branch")

  assert.EqualValues(t, "ends_with", ruleset.GetRules().GetCommitMessagePattern().Operator, "Expected default protection to be on branch")
  assert.EqualValues(t, "test", ruleset.GetRules().GetCommitMessagePattern().Pattern, "Expected default protection to be on branch")
  assert.EqualValues(t, "Test message", ruleset.GetRules().GetCommitMessagePattern().GetName(), "Expected default protection to be on branch")
  assert.EqualValues(t, false, ruleset.GetRules().GetCommitMessagePattern().GetNegate(), "Expected default protection to be on branch")

  assert.EqualValues(t, "contains", ruleset.GetRules().GetCommitterEmailPattern().Operator, "Expected default protection to be on branch")
  assert.EqualValues(t, "test@example.com", ruleset.GetRules().GetCommitterEmailPattern().Pattern, "Expected default protection to be on branch")
  assert.EqualValues(t, "Test committer email", ruleset.GetRules().GetCommitterEmailPattern().GetName(), "Expected default protection to be on branch")
  assert.EqualValues(t, false, ruleset.GetRules().GetCommitterEmailPattern().GetNegate(), "Expected default protection to be on branch")

  assert.NotNil(t, ruleset.GetRules().GetCreation(), "Expected default protection to be on branch")
  assert.Nil(t, ruleset.GetRules().GetDeletion(), "Expected default protection to be on branch")
  assert.NotNil(t, ruleset.GetRules().GetNonFastForward(), "Expected default protection to be on branch")

  // assert.EqualValues(t, 10, ruleset.GetRules().GetMergeQueue().CheckResponseTimeoutMinutes, "Expected default protection to be on branch")
  // assert.EqualValues(t, "ALLGREEN", ruleset.GetRules().GetMergeQueue().GroupingStrategy, "Expected default protection to be on branch")
  // assert.EqualValues(t, 10, ruleset.GetRules().GetMergeQueue().MaxEntriesToBuild, "Expected default protection to be on branch")
  // assert.EqualValues(t, 15, ruleset.GetRules().GetMergeQueue().MaxEntriesToMerge, "Expected default protection to be on branch")
  // assert.EqualValues(t, "MERGE", ruleset.GetRules().GetMergeQueue().MergeMethod, "Expected default protection to be on branch")
  // assert.EqualValues(t, 1, ruleset.GetRules().GetMergeQueue().MinEntriesToMerge, "Expected default protection to be on branch")
  // assert.EqualValues(t, 10, ruleset.GetRules().GetMergeQueue().MinEntriesToMergeWaitMinutes, "Expected default protection to be on branch")

  assert.EqualValues(t, true, ruleset.GetRules().GetPullRequest().DismissStaleReviewsOnPush, "Expected default protection to be on branch")
  assert.EqualValues(t, true, ruleset.GetRules().GetPullRequest().RequireCodeOwnerReview, "Expected default protection to be on branch")
  assert.EqualValues(t, true, ruleset.GetRules().GetPullRequest().RequireLastPushApproval, "Expected default protection to be on branch")
  assert.EqualValues(t, 1, ruleset.GetRules().GetPullRequest().RequiredApprovingReviewCount, "Expected default protection to be on branch")
  assert.EqualValues(t, true, ruleset.GetRules().GetPullRequest().RequiredReviewThreadResolution, "Expected default protection to be on branch")

  assert.EqualValues(t, 2, len(ruleset.GetRules().GetRequiredDeployments().RequiredDeploymentEnvironments), "Expected default protection to be on branch")
  assert.EqualValues(t, "staging", ruleset.GetRules().GetRequiredDeployments().RequiredDeploymentEnvironments[0], "Expected default protection to be on branch")
  assert.EqualValues(t, "production", ruleset.GetRules().GetRequiredDeployments().RequiredDeploymentEnvironments[1], "Expected default protection to be on branch")

  assert.EqualValues(t, 2, len(ruleset.GetRules().GetRequiredStatusChecks().RequiredStatusChecks), "Expected default protection to be on branch")
  assert.EqualValues(t, "test2", ruleset.GetRules().GetRequiredStatusChecks().RequiredStatusChecks[0].Context, "Expected default protection to be on branch")
  assert.EqualValues(t, int64(1199797), *ruleset.GetRules().GetRequiredStatusChecks().RequiredStatusChecks[0].IntegrationID, "Expected default protection to be on branch")
  assert.EqualValues(t, "test", ruleset.GetRules().GetRequiredStatusChecks().RequiredStatusChecks[1].Context, "Expected default protection to be on branch")
  assert.EqualValues(t, true, ruleset.GetRules().GetRequiredStatusChecks().StrictRequiredStatusChecksPolicy, "Expected default protection to be on branch")
  assert.EqualValues(t, true, *ruleset.GetRules().GetRequiredStatusChecks().DoNotEnforceOnCreate, "Expected default protection to be on branch")

  // assert.EqualValues(t, "regexp", ruleset.GetRules().GetTagNamePattern().Operator, "Expected default protection to be on branch")
  // assert.EqualValues(t, "^v\\d+\\.\\d+\\.\\d+$", ruleset.GetRules().GetTagNamePattern().Pattern, "Expected default protection to be on branch")
  // assert.EqualValues(t, "Tag name", ruleset.GetRules().GetTagNamePattern().GetName(), "Expected default protection to be on branch")
  // assert.EqualValues(t, false, ruleset.GetRules().GetTagNamePattern().GetNegate(), "Expected default protection to be on branch")


  // Unsupported due to drift. https://github.com/integrations/terraform-provider-github/pull/2701
  // assert.EqualValues(t, 1, len(ruleset.GetRules().GetCodeScanning().CodeScanningTools), "Expected default protection to be on branch")
  // assert.EqualValues(t, "errors", ruleset.GetRules().GetCodeScanning().CodeScanningTools[0].AlertsThreshold, "Expected default protection to be on branch")
  // assert.EqualValues(t, "high_or_higher", ruleset.GetRules().GetCodeScanning().CodeScanningTools[0].SecurityAlertsThreshold, "Expected default protection to be on branch")
  // assert.EqualValues(t, "CodeQL", ruleset.GetRules().GetCodeScanning().CodeScanningTools[0].Tool, "Expected default protection to be on branch")

  // assert.Equal(t, true, repo.GetAutomatedSecurityFixes())
  // assert.Equal(t, true, repo.GetVulnerabilityAlerts())


  //expectedExampleInput := "Hello, world!"

  // Run `terraform output` to get the value of an output variable
  // id := terraform.Output(t, terraformOptions, "id")
  // example := terraform.Output(t, terraformOptions, "example")
  // random := terraform.Output(t, terraformOptions, "random")

  // Verify we're getting back the outputs we expect
  // Ensure we get a random number appended
  // assert.Equal(t, expectedExampleInput+" "+random, example)
  // Ensure we get the attribute included in the ID
  // assert.Equal(t, "eg-ue2-test-example-"+randID, id)

  // ************************************************************************
  // This steps below are unusual, not generally part of the testing
  // but included here as an example of testing this specific module.
  // This module has a random number that is supposed to change
  // only when the example changes. So we run it again to ensure
  // it does not change.

  // This will run `terraform apply` a second time and fail the test if there are any errors
  terraform.Apply(t, terraformOptions)

  // id2 := terraform.Output(t, terraformOptions, "id")
  // example2 := terraform.Output(t, terraformOptions, "example")
  // random2 := terraform.Output(t, terraformOptions, "random")

  // assert.Equal(t, id, id2, "Expected `id` to be stable")
  // assert.Equal(t, example, example2, "Expected `example` to be stable")
  // assert.Equal(t, random, random2, "Expected `random` to be stable")

  // // Then we run change the example and run it a third time and
  // verify that the random number changed
  // newExample := "Goodbye"
  // terraformOptions.Vars["example_input_override"] = newExample
  // terraform.Apply(t, terraformOptions)

  // example3 := terraform.Output(t, terraformOptions, "example")
  // random3 := terraform.Output(t, terraformOptions, "random")

  // assert.NotEqual(t, random, random3, "Expected `random` to change when `example` changed")
  // assert.Equal(t, newExample+" "+random3, example3, "Expected `example` to use new random number")
}

func TestExamplesCompleteDisabled(t *testing.T) {
  t.Parallel()
  randID := strings.ToLower(random.UniqueId())
  attributes := []string{randID}

  rootFolder := "../../"
  terraformFolderRelativeToRoot := "examples/complete"
  varFiles := []string{"fixtures.us-east-2.tfvars"}

  tempTestFolder := testStructure.CopyTerraformFolderToTemp(t, rootFolder, terraformFolderRelativeToRoot)

  terraformOptions := &terraform.Options{
    // The path to where our Terraform code is located
    TerraformDir: tempTestFolder,
    Upgrade:      true,
    // Variables to pass to our Terraform code using -var-file options
    VarFiles: varFiles,
    Vars: map[string]interface{}{
      "attributes": attributes,
      "enabled":    "false",
    },
  }

  // At the end of the test, run `terraform destroy` to clean up any resources that were created
  defer cleanup(t, terraformOptions, tempTestFolder)

  // This will run `terraform init` and `terraform apply` and fail the test if there are any errors
  results := terraform.InitAndApply(t, terraformOptions)

  // Should complete successfully without creating or changing any resources
  assert.Contains(t, results, "Resources: 0 added, 0 changed, 0 destroyed.")
}
