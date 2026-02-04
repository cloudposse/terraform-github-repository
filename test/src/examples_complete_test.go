package test

import (
  "os"
  "strings"
  "testing"
  "context"
  "fmt"
  "crypto/rand"
  "crypto/rsa"
  "golang.org/x/crypto/ssh"

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

  terraformOptions := &terraform.Options{
    // The path to where our Terraform code is located
    TerraformDir: tempTestFolder,
    Upgrade:      true,
    // Variables to pass to our Terraform code using -var-file options
    VarFiles: varFiles,
    Vars: map[string]interface{}{
      "enabled":    true,
      "name": repositoryName,
      "visibility": "public",
    },
  }

  // At the end of the test, run `terraform destroy` to clean up any resources that were created
  defer cleanup(t, terraformOptions, tempTestFolder)

  // This will run `terraform init` and `terraform apply` and fail the test if there are any errors
  terraform.InitAndApply(t, terraformOptions)

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
  assert.Equal(t, 1, len(commits))

  topics, _, err := client.Repositories.ListAllTopics(context.Background(), owner, repositoryName)
  assert.NoError(t, err)
  assert.ElementsMatch(t, []string{"terraform", "github", "test"}, topics)

  autolinkReferences, _, err := client.Repositories.ListAutolinks(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.Equal(t, 1, len(autolinkReferences))
  assert.Equal(t, "JIRA-", autolinkReferences[0].GetKeyPrefix())
  assert.Equal(t, "https://jira.example.com/browse/<num>", autolinkReferences[0].GetURLTemplate())

  // Get repository environments and add assertions
  // Note: GitHub Pages automatically creates a "github-pages" environment when enabled
  envs, _, err := client.Repositories.ListEnvironments(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, envs)
  assert.Equal(t, 4, len(envs.Environments)) // staging, development, production + github-pages (auto-created by Pages)

  env, _, err := client.Repositories.GetEnvironment(context.Background(), owner, repositoryName, "staging")
  assert.NoError(t, err)
  assert.NotNil(t, env)

  assert.Equal(t, true, env.GetCanAdminsBypass())
  assert.Equal(t, 2, len(env.ProtectionRules))

  assert.Equal(t, "wait_timer", env.ProtectionRules[0].GetType())
  assert.Equal(t, 1, env.ProtectionRules[0].GetWaitTimer())

  assert.Equal(t, "branch_policy", env.ProtectionRules[1].GetType())
  // TODO: Fix - Prevent self review is not supported without reviewers specified
  // assert.Equal(t, true, env.ProtectionRules[1].GetPreventSelfReview(), "Expected prevent_self_review to be true for staging")

  deploymentBranchPolicies, _, err := client.Repositories.ListDeploymentBranchPolicies(context.Background(), owner, repositoryName, "staging")
	assert.Error(t, err)

  env, _, err = client.Repositories.GetEnvironment(context.Background(), owner, repositoryName, "development")
  assert.NoError(t, err)
  assert.NotNil(t, env)

  assert.Equal(t, false, env.GetCanAdminsBypass())
  assert.Equal(t, 1, len(env.ProtectionRules))
  assert.Equal(t, "wait_timer", env.ProtectionRules[0].GetType())
  assert.Equal(t, 5, env.ProtectionRules[0].GetWaitTimer())

  deploymentBranchPolicies, _, err = client.Repositories.ListDeploymentBranchPolicies(context.Background(), owner, repositoryName, "development")
	assert.Error(t, err)

  env, _, err = client.Repositories.GetEnvironment(context.Background(), owner, repositoryName, "production")
  assert.NoError(t, err)
  assert.NotNil(t, env)

  assert.Equal(t, false, env.GetCanAdminsBypass())
  assert.Equal(t, 2, len(env.ProtectionRules))
  assert.Equal(t, "wait_timer", env.ProtectionRules[0].GetType())
  assert.Equal(t, 10, env.ProtectionRules[0].GetWaitTimer())
  assert.Equal(t, "branch_policy", env.ProtectionRules[1].GetType())

	deploymentBranchPolicies, _, err = client.Repositories.ListDeploymentBranchPolicies(context.Background(), owner, repositoryName, "production")
	assert.NoError(t, err)
	assert.NotNil(t, deploymentBranchPolicies)
	assert.Equal(t, 2, len(deploymentBranchPolicies.BranchPolicies))

	branchPolicy, _, err := client.Repositories.GetDeploymentBranchPolicy(context.Background(), owner, repositoryName, "production", deploymentBranchPolicies.BranchPolicies[0].GetID())
  assert.NoError(t, err)
  assert.NotNil(t, branchPolicy)
  assert.Equal(t, "branch", branchPolicy.GetType())
  assert.Equal(t, "main", branchPolicy.GetName())

	branchPolicy, _, err = client.Repositories.GetDeploymentBranchPolicy(context.Background(), owner, repositoryName, "production", deploymentBranchPolicies.BranchPolicies[1].GetID())
  assert.NoError(t, err)
  assert.NotNil(t, branchPolicy)
  assert.Equal(t, "tag", branchPolicy.GetType())
  assert.Equal(t, "v1.0.0", branchPolicy.GetName())

  envVars, _, err := client.Actions.ListEnvVariables(context.Background(), owner, repositoryName, "staging", nil)
  assert.NoError(t, err)
  assert.NotNil(t, envVars)
  assert.Equal(t, 2, len(envVars.Variables))

  assertVariables(t, envVars.Variables, map[string]string{
    "TEST_VARIABLE":   "test-value",
    "TEST_VARIABLE_2": "test-value-2",
  })

  envSecrets, _, err := client.Actions.ListEnvSecrets(context.Background(), int(repo.GetID()), "production", nil)
  assert.NoError(t, err)
  assert.NotNil(t, envSecrets)
  assert.Equal(t, 2, len(envSecrets.Secrets))

  assertSecretNames(t, envSecrets.Secrets, []string{"TEST_SECRET", "TEST_SECRET_2"})

  vars, _, err := client.Actions.ListRepoVariables(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, vars)
  assert.Equal(t, 2, len(vars.Variables))

  assertVariables(t, vars.Variables, map[string]string{
    "TEST_VARIABLE":   "test-value",
    "TEST_VARIABLE_2": "test-value-2",
  })

  secrets, _, err := client.Actions.ListRepoSecrets(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, secrets)
  assert.Equal(t, 2, len(secrets.Secrets))
  assertSecretNames(t, secrets.Secrets, []string{"TEST_SECRET", "TEST_SECRET_2"})

  webhooks, _, err := client.Repositories.ListHooks(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, webhooks)
  assert.Equal(t, 1, len(webhooks))

  webhook := webhooks[0]
  assert.Equal(t, "Repository", webhook.GetType())
  assert.Equal(t, "web", webhook.GetName())
  assert.NotNil(t, webhook.GetConfig())
  assert.Equal(t, "https://hooks.example.com/github", webhook.GetConfig().GetURL())
  assert.Equal(t, "json", webhook.GetConfig().GetContentType())
  assert.Equal(t, "0", webhook.GetConfig().GetInsecureSSL())
  assert.Equal(t, "********", webhook.GetConfig().GetSecret())
  assert.ElementsMatch(t, []string{"push", "pull_request"}, webhook.Events)
  assert.Equal(t, true, webhook.GetActive())

  labels, _, err := client.Issues.ListLabels(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, labels)

  // Refactored: Assert labels by name using a map for easier lookup
  labelMap := make(map[string]*github.Label)
  for _, label := range labels {
    labelMap[label.GetName()] = label
  }
  bug2Label, bug2Exists := labelMap["bug2"]
  feature2Label, feature2Exists := labelMap["feature2"]

  assert.True(t, bug2Exists)
  assert.True(t, feature2Exists)

  assert.Equal(t, "a73a4a", bug2Label.GetColor())
  assert.Equal(t, "🐛 An issue with the system", bug2Label.GetDescription())

  assert.Equal(t, "336699", feature2Label.GetColor())
  assert.Equal(t, "New functionality", feature2Label.GetDescription())

  // Get rulesets
  // Note: Push rulesets are not supported on public repositories, so we only test branch and tag rulesets here.
  // The fixtures include a commented-out push_restrictions example for private repository use.
  rulesets, _, err := client.Repositories.GetAllRulesets(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, rulesets)
  assert.Equal(t, 2, len(rulesets)) // branch (default) + tag (tag_protection)

  ruleset, _, err := client.Repositories.GetRuleset(context.Background(), owner, repositoryName, rulesets[0].GetID(), true)
  assert.NoError(t, err)
  assert.NotNil(t, ruleset)

  assert.Equal(t, "Default protection", ruleset.Name)
  assert.EqualValues(t, "active", ruleset.Enforcement)
  assert.EqualValues(t, "Repository", *ruleset.SourceType)
  assert.EqualValues(t, "branch", *ruleset.Target)
  assert.EqualValues(t, fmt.Sprintf("%s/%s", owner, repositoryName), ruleset.Source)
  assert.EqualValues(t, "~ALL", ruleset.GetConditions().RefName.Include[0])
  assert.EqualValues(t, "refs/heads/releases", ruleset.GetConditions().RefName.Exclude[0])
  assert.EqualValues(t, "refs/heads/main", ruleset.GetConditions().RefName.Exclude[1])

  assert.EqualValues(t, 4, len(ruleset.BypassActors))
  assert.EqualValues(t, "always", *ruleset.BypassActors[0].GetBypassMode())
  assert.EqualValues(t, "OrganizationAdmin", *ruleset.BypassActors[0].GetActorType())
  assert.Equal(t, int64(0), ruleset.BypassActors[0].GetActorID())

  assert.EqualValues(t, "pull_request", *ruleset.BypassActors[1].GetBypassMode())
  assert.EqualValues(t, "RepositoryRole", *ruleset.BypassActors[1].GetActorType())
  assert.Equal(t, int64(2), ruleset.BypassActors[1].GetActorID())

  assert.EqualValues(t, "pull_request", *ruleset.BypassActors[2].GetBypassMode())
  assert.EqualValues(t, "RepositoryRole", *ruleset.BypassActors[2].GetActorType())
  assert.Equal(t, int64(4), ruleset.BypassActors[2].GetActorID())

  assert.EqualValues(t, "pull_request", *ruleset.BypassActors[3].GetBypassMode())
  assert.EqualValues(t, "RepositoryRole", *ruleset.BypassActors[3].GetActorType())
  assert.Equal(t, int64(5), ruleset.BypassActors[3].GetActorID())

  assert.EqualValues(t, "starts_with", ruleset.GetRules().GetBranchNamePattern().Operator)
  assert.EqualValues(t, "release", ruleset.GetRules().GetBranchNamePattern().Pattern)
  assert.EqualValues(t, "Release branch", ruleset.GetRules().GetBranchNamePattern().GetName())
  assert.EqualValues(t, false, ruleset.GetRules().GetBranchNamePattern().GetNegate())

  assert.EqualValues(t, "contains", ruleset.GetRules().GetCommitAuthorEmailPattern().Operator)
  assert.EqualValues(t, "gmail.com", ruleset.GetRules().GetCommitAuthorEmailPattern().Pattern)
  assert.EqualValues(t, "Gmail email", ruleset.GetRules().GetCommitAuthorEmailPattern().GetName())
  assert.EqualValues(t, true, ruleset.GetRules().GetCommitAuthorEmailPattern().GetNegate())

  assert.EqualValues(t, "ends_with", ruleset.GetRules().GetCommitMessagePattern().Operator)
  assert.EqualValues(t, "test", ruleset.GetRules().GetCommitMessagePattern().Pattern)
  assert.EqualValues(t, "Test message", ruleset.GetRules().GetCommitMessagePattern().GetName())
  assert.EqualValues(t, false, ruleset.GetRules().GetCommitMessagePattern().GetNegate())

  assert.EqualValues(t, "contains", ruleset.GetRules().GetCommitterEmailPattern().Operator)
  assert.EqualValues(t, "test@example.com", ruleset.GetRules().GetCommitterEmailPattern().Pattern)
  assert.EqualValues(t, "Test committer email", ruleset.GetRules().GetCommitterEmailPattern().GetName())
  assert.EqualValues(t, false, ruleset.GetRules().GetCommitterEmailPattern().GetNegate())

  assert.NotNil(t, ruleset.GetRules().GetCreation())
  assert.Nil(t, ruleset.GetRules().GetDeletion())
  assert.NotNil(t, ruleset.GetRules().GetNonFastForward())

  assert.EqualValues(t, true, ruleset.GetRules().GetPullRequest().DismissStaleReviewsOnPush)
  assert.EqualValues(t, true, ruleset.GetRules().GetPullRequest().RequireCodeOwnerReview)
  assert.EqualValues(t, true, ruleset.GetRules().GetPullRequest().RequireLastPushApproval)
  assert.EqualValues(t, 1, ruleset.GetRules().GetPullRequest().RequiredApprovingReviewCount)
  assert.EqualValues(t, true, ruleset.GetRules().GetPullRequest().RequiredReviewThreadResolution)

  assert.EqualValues(t, 2, len(ruleset.GetRules().GetRequiredDeployments().RequiredDeploymentEnvironments))
  assert.EqualValues(t, "staging", ruleset.GetRules().GetRequiredDeployments().RequiredDeploymentEnvironments[0])
  assert.EqualValues(t, "production", ruleset.GetRules().GetRequiredDeployments().RequiredDeploymentEnvironments[1])

  assert.EqualValues(t, 1, len(ruleset.GetRules().GetRequiredStatusChecks().RequiredStatusChecks))
  assert.EqualValues(t, "test", ruleset.GetRules().GetRequiredStatusChecks().RequiredStatusChecks[0].Context)
  assert.EqualValues(t, true, ruleset.GetRules().GetRequiredStatusChecks().StrictRequiredStatusChecksPolicy)
  assert.EqualValues(t, true, *ruleset.GetRules().GetRequiredStatusChecks().DoNotEnforceOnCreate)

  // Unsupported due to drift. https://github.com/integrations/terraform-provider-github/pull/2701
  // assert.EqualValues(t, 1, len(ruleset.GetRules().GetCodeScanning().CodeScanningTools), "Expected default protection to be on branch")
  // assert.EqualValues(t, "errors", ruleset.GetRules().GetCodeScanning().CodeScanningTools[0].AlertsThreshold, "Expected default protection to be on branch")
  // assert.EqualValues(t, "high_or_higher", ruleset.GetRules().GetCodeScanning().CodeScanningTools[0].SecurityAlertsThreshold, "Expected default protection to be on branch")
  // assert.EqualValues(t, "CodeQL", ruleset.GetRules().GetCodeScanning().CodeScanningTools[0].Tool, "Expected default protection to be on branch")

  // This will run `terraform apply` a second time and fail the test if there are any errors
  terraform.Apply(t, terraformOptions)

  // Read terraform outputs and assert them
  fullName := terraform.Output(t, terraformOptions, "full_name")
  gitCloneUrl := terraform.Output(t, terraformOptions, "git_clone_url")
  htmlUrl := terraform.Output(t, terraformOptions, "html_url")
  sshCloneUrl := terraform.Output(t, terraformOptions, "ssh_clone_url")
  svnUrl := terraform.Output(t, terraformOptions, "svn_url")
  repoId := terraform.Output(t, terraformOptions, "repo_id")
  nodeId := terraform.Output(t, terraformOptions, "node_id")
  primaryLanguage := terraform.Output(t, terraformOptions, "primary_language")
  webhooksUrls := terraform.OutputMap(t, terraformOptions, "webhooks_urls")
  collaboratorsInvitationIds := terraform.OutputList(t, terraformOptions, "collaborators_invitation_ids")
  rulesetsEtags := terraform.OutputMap(t, terraformOptions, "rulesets_etags")
  rulesetsNodeIds := terraform.OutputMap(t, terraformOptions, "rulesets_node_ids")
  rulesetsRulesIds := terraform.OutputMap(t, terraformOptions, "rulesets_rules_ids")

  assert.Equal(t, fullName, fmt.Sprintf("%s/%s", owner, repositoryName))
  assert.Equal(t, gitCloneUrl, fmt.Sprintf("git://github.com/%s/%s.git", owner, repositoryName))
  assert.Equal(t, htmlUrl, fmt.Sprintf("https://github.com/%s/%s", owner, repositoryName))
  assert.Equal(t, sshCloneUrl, fmt.Sprintf("git@github.com:%s/%s.git", owner, repositoryName))
  assert.Equal(t, svnUrl, fmt.Sprintf("https://github.com/%s/%s", owner, repositoryName))
  assert.Equal(t, repoId, fmt.Sprintf("%d", repo.GetID()))
  assert.Equal(t, nodeId, repo.GetNodeID())
  assert.Equal(t, primaryLanguage, repo.GetLanguage())

  assert.Equal(t, 1, len(webhooksUrls))
  assert.Equal(t, fmt.Sprintf("https://api.github.com/repos/%s/%s/hooks/%d", owner, repositoryName, webhook.GetID()), webhooksUrls["notify-on-push"])
  assert.Equal(t, 0, len(collaboratorsInvitationIds))
  assert.Equal(t, 2, len(rulesetsEtags))      // branch + tag rulesets
  assert.Equal(t, 2, len(rulesetsNodeIds))    // branch + tag rulesets
  assert.Equal(t, 2, len(rulesetsRulesIds))   // branch + tag rulesets
}

// Test the Terraform module in examples/minimum using Terratest.
func TestExamplesMinimum(t *testing.T) {
  t.Parallel()
  randID := strings.ToLower(random.UniqueId())

  rootFolder := "../../"
  terraformFolderRelativeToRoot := "examples/minimum"
  varFiles := []string{"fixtures.us-east-2.tfvars"}

  tempTestFolder := testStructure.CopyTerraformFolderToTemp(t, rootFolder, terraformFolderRelativeToRoot)

  repositoryName := fmt.Sprintf("terraform-github-repository-test-%s", randID)

  deployKey, err := generateRSAKey()
  assert.NoError(t, err)

  githubTestUser := "cloudposse-test-bot"

  terraformOptions := &terraform.Options{
    // The path to where our Terraform code is located
    TerraformDir: tempTestFolder,
    Upgrade:      true,
    // Variables to pass to our Terraform code using -var-file options
    VarFiles: varFiles,
    Vars: map[string]interface{}{
      "enabled":    true,
      "name": repositoryName,
      "visibility": "public",
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
          "wait_timer": 0,
          "can_admins_bypass": true,
          "prevent_self_review": true,
          "reviewers": map[string]interface{}{
            // Teams are not supported yet
            //"teams": []string{"test-team"},
            "users": []string{githubTestUser},
          },
        },
      },
      "deploy_keys": map[string]interface{}{
        "cicd-key": map[string]interface{}{
          "title": "CI/CD Deploy Key",
          "key": deployKey,
          "read_only": true,
        },
      },
      "teams": map[string]interface{}{
        "admin": "admin",
        "test-team": "push",
      },
      "users": map[string]interface{}{
        githubTestUser: "admin",
      },
      "rulesets": map[string]interface{}{
        "default": map[string]interface{}{
          "name": "Default protection",
          "enforcement": "active",
          "target": "branch",
          "conditions": map[string]interface{}{
            "ref_name": map[string]interface{}{
              "include": []string{"main"},
            },
          },
          "bypass_actors": []map[string]interface{}{
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
            "merge_queue": map[string]interface{}{
              "check_response_timeout_minutes": 10,
              "grouping_strategy": "ALLGREEN",
              "max_entries_to_build": 10,
              "max_entries_to_merge": 15,
              "merge_method": "MERGE",
              "min_entries_to_merge": 1,
              "min_entries_to_merge_wait_minutes": 10,
            },
            "required_status_checks": map[string]interface{}{
              "required_check": []map[string]interface{}{
                {
                  "context": "test",
                  "integration_id": "1199797",
                },
              },
              "strict_required_status_checks_policy": true,
              "do_not_enforce_on_create": true,
            },
          },
        },
      },
    },
  }

  // At the end of the test, run `terraform destroy` to clean up any resources that were created
  defer cleanup(t, terraformOptions, tempTestFolder)

  // This will run `terraform init` and `terraform apply` and fail the test if there are any errors
  terraform.InitAndApply(t, terraformOptions)

  token := os.Getenv("GITHUB_TOKEN")

  client := github.NewClient(nil).WithAuthToken(token)

  repo, _, err := client.Repositories.Get(context.Background(), owner, repositoryName)
  assert.NoError(t, err)

  assert.Equal(t, "public", repo.GetVisibility())

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
  assert.Equal(t, 1, len(envs.Environments))

  env, _, err := client.Repositories.GetEnvironment(context.Background(), owner, repositoryName, "staging")
  assert.NoError(t, err)
  assert.NotNil(t, env)

  assert.Equal(t, true, env.GetCanAdminsBypass())
  assert.Equal(t, 1, len(env.ProtectionRules))
  assert.Equal(t, "required_reviewers", env.ProtectionRules[0].GetType())

  assert.Equal(t, 1, len(env.ProtectionRules[0].Reviewers))
  assert.Equal(t, "User", env.ProtectionRules[0].Reviewers[0].GetType())
  assert.Equal(t, true, env.ProtectionRules[0].GetPreventSelfReview())

  reviewerUser := env.ProtectionRules[0].Reviewers[0].Reviewer
  githubUser, ok := reviewerUser.(*github.User)
  assert.True(t, ok, "Expected reviewerUser to be of type *github.User")
  assert.Equal(t, "cloudposse-test-bot", githubUser.GetLogin())

  deployKeys, _, err := client.Repositories.ListKeys(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, deployKeys)
  assert.Equal(t, 1, len(deployKeys))
  assert.Equal(t, "CI/CD Deploy Key", deployKeys[0].GetTitle())

  teams, _, err := client.Repositories.ListTeams(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, teams)
  assert.Equal(t, 2, len(teams))
  assert.Equal(t, "admin", teams[0].GetName())
  assert.Equal(t, "admin", teams[0].GetPermission())
  assert.Equal(t, "test-team", teams[1].GetName())
  assert.Equal(t, "push", teams[1].GetPermission())

  test_team := teams[1]

  users, _, err := client.Repositories.ListCollaborators(context.Background(), owner, repositoryName, &github.ListCollaboratorsOptions{Permission: "admin"})
  assert.NoError(t, err)
  assert.NotNil(t, users)
  assert.GreaterOrEqual(t, len(users), 1)

  var foundUser bool
  for _, user := range users {
    if user.GetLogin() == "cloudposse-test-bot" {
      foundUser = true
      break
    }
  }
  assert.True(t, foundUser)


  rulesets, _, err := client.Repositories.GetAllRulesets(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, rulesets)
  assert.Equal(t, 1, len(rulesets))

  ruleset, _, err := client.Repositories.GetRuleset(context.Background(), owner, repositoryName, rulesets[0].GetID(), true)
  assert.NoError(t, err)
  assert.NotNil(t, ruleset)

  assert.Equal(t, "Default protection", ruleset.Name)
  assert.EqualValues(t, "active", ruleset.Enforcement)
  assert.EqualValues(t, "Repository", *ruleset.SourceType)
  assert.EqualValues(t, "branch", *ruleset.Target)
  assert.EqualValues(t, fmt.Sprintf("%s/%s", owner, repositoryName), ruleset.Source)
  assert.EqualValues(t, "refs/heads/main", ruleset.GetConditions().RefName.Include[0])

  assert.EqualValues(t, 2, len(ruleset.BypassActors))
  assert.EqualValues(t, "always", *ruleset.BypassActors[0].GetBypassMode())
  assert.EqualValues(t, "Integration", *ruleset.BypassActors[0].GetActorType())
  assert.Equal(t, int64(1199797), ruleset.BypassActors[0].GetActorID())

  assert.EqualValues(t, "always", *ruleset.BypassActors[1].GetBypassMode())
  assert.EqualValues(t, "Team", *ruleset.BypassActors[1].GetActorType())
  assert.Equal(t, test_team.GetID(), ruleset.BypassActors[1].GetActorID())

  assert.EqualValues(t, 10, ruleset.GetRules().GetMergeQueue().CheckResponseTimeoutMinutes)
  assert.EqualValues(t, "ALLGREEN", ruleset.GetRules().GetMergeQueue().GroupingStrategy)
  assert.EqualValues(t, 10, ruleset.GetRules().GetMergeQueue().MaxEntriesToBuild)
  assert.EqualValues(t, 15, ruleset.GetRules().GetMergeQueue().MaxEntriesToMerge)
  assert.EqualValues(t, "MERGE", ruleset.GetRules().GetMergeQueue().MergeMethod)
  assert.EqualValues(t, 1, ruleset.GetRules().GetMergeQueue().MinEntriesToMerge)
  assert.EqualValues(t, 10, ruleset.GetRules().GetMergeQueue().MinEntriesToMergeWaitMinutes)

  assert.EqualValues(t, 1, len(ruleset.GetRules().GetRequiredStatusChecks().RequiredStatusChecks))
  assert.EqualValues(t, "test", ruleset.GetRules().GetRequiredStatusChecks().RequiredStatusChecks[0].Context)
  assert.EqualValues(t, int64(1199797), *ruleset.GetRules().GetRequiredStatusChecks().RequiredStatusChecks[0].IntegrationID)
  assert.EqualValues(t, true, ruleset.GetRules().GetRequiredStatusChecks().StrictRequiredStatusChecksPolicy)
  assert.EqualValues(t, true, *ruleset.GetRules().GetRequiredStatusChecks().DoNotEnforceOnCreate)

  // This will run `terraform apply` a second time and fail the test if there are any errors
  terraform.Apply(t, terraformOptions)
}

// Test the Terraform module in examples/minimum using Terratest.
func TestExamplesTagsRulesets(t *testing.T) {
  t.Parallel()
  randID := strings.ToLower(random.UniqueId())

  rootFolder := "../../"
  terraformFolderRelativeToRoot := "examples/minimum"
  varFiles := []string{"fixtures.us-east-2.tfvars"}

  tempTestFolder := testStructure.CopyTerraformFolderToTemp(t, rootFolder, terraformFolderRelativeToRoot)

  repositoryName := fmt.Sprintf("terraform-github-repository-test-%s", randID)

  terraformOptions := &terraform.Options{
    // The path to where our Terraform code is located
    TerraformDir: tempTestFolder,
    Upgrade:      true,
    // Variables to pass to our Terraform code using -var-file options
    VarFiles: varFiles,
    Vars: map[string]interface{}{
      "enabled":    true,
      "name": repositoryName,
      "visibility": "public",
      "rulesets": map[string]interface{}{
        "default": map[string]interface{}{
          "name": "Default protection",
          "enforcement": "active",
          "target": "tag",
          "conditions": map[string]interface{}{
            "ref_name": map[string]interface{}{
              "include": []string{"v.*"},
            },
          },
          "rules": map[string]interface{}{
            "tag_name_pattern": map[string]interface{}{
              "operator": "regex",
              "pattern": "v.*",
              "name": "Tag name",
              "negate": false,
            },
          },
        },
      },
    },
  }

  // At the end of the test, run `terraform destroy` to clean up any resources that were created
  defer cleanup(t, terraformOptions, tempTestFolder)

  // This will run `terraform init` and `terraform apply` and fail the test if there are any errors
  terraform.InitAndApply(t, terraformOptions)

  token := os.Getenv("GITHUB_TOKEN")

  client := github.NewClient(nil).WithAuthToken(token)

  repo, _, err := client.Repositories.Get(context.Background(), owner, repositoryName)
  assert.NoError(t, err)

  assert.Equal(t, "public", repo.GetVisibility())

  rulesets, _, err := client.Repositories.GetAllRulesets(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.NotNil(t, rulesets)
  assert.Equal(t, 1, len(rulesets))

  ruleset, _, err := client.Repositories.GetRuleset(context.Background(), owner, repositoryName, rulesets[0].GetID(), true)
  assert.NoError(t, err)
  assert.NotNil(t, ruleset)

  assert.Equal(t, "Default protection", ruleset.Name)
  assert.EqualValues(t, "active", ruleset.Enforcement)
  assert.EqualValues(t, "Repository", *ruleset.SourceType )
  assert.EqualValues(t, "tag", *ruleset.Target)
  assert.EqualValues(t, fmt.Sprintf("%s/%s", owner, repositoryName), ruleset.Source)
  assert.EqualValues(t, "refs/tags/v.*", ruleset.GetConditions().RefName.Include[0])

  assert.EqualValues(t, "regex", ruleset.GetRules().GetTagNamePattern().Operator)
  assert.EqualValues(t, "v.*", ruleset.GetRules().GetTagNamePattern().Pattern)
  assert.EqualValues(t, "Tag name", ruleset.GetRules().GetTagNamePattern().GetName())
  assert.EqualValues(t, false, ruleset.GetRules().GetTagNamePattern().GetNegate())

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

// Test the Terraform module in examples/minimum using Terratest.
func TestExamplesFromTemplate(t *testing.T) {
  t.Parallel()
  randID := strings.ToLower(random.UniqueId())

  rootFolder := "../../"
  terraformFolderRelativeToRoot := "examples/minimum"
  varFiles := []string{"fixtures.us-east-2.tfvars"}

  tempTestFolder := testStructure.CopyTerraformFolderToTemp(t, rootFolder, terraformFolderRelativeToRoot)

  repositoryName := fmt.Sprintf("terraform-github-repository-test-%s", randID)

  terraformOptions := &terraform.Options{
    // The path to where our Terraform code is located
    TerraformDir: tempTestFolder,
    Upgrade:      true,
    // Variables to pass to our Terraform code using -var-file options
    VarFiles: varFiles,
    Vars: map[string]interface{}{
      "enabled":    true,
      "name": repositoryName,
      "visibility": "public",
      "template": map[string]interface{}{
        "owner": "cloudposse-tests",
        "name": "test-terraform-github-repository-template",
        "include_all_branches": true,
      },
    },
  }

  // At the end of the test, run `terraform destroy` to clean up any resources that were created
  defer cleanup(t, terraformOptions, tempTestFolder)

  // This will run `terraform init` and `terraform apply` and fail the test if there are any errors
  terraform.InitAndApply(t, terraformOptions)

  token := os.Getenv("GITHUB_TOKEN")

  client := github.NewClient(nil).WithAuthToken(token)

  repo, _, err := client.Repositories.Get(context.Background(), owner, repositoryName)
  assert.NoError(t, err)

  // Check if the repository was auto-initialized
  commits, _, err := client.Repositories.ListCommits(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)
  assert.Equal(t, 1, len(commits))

  readmeContent, _, err := client.Repositories.GetReadme(context.Background(), owner, repositoryName, nil)
  assert.NoError(t, err)

  readmeData, err := readmeContent.GetContent()
  assert.NoError(t, err)
  assert.Contains(t, readmeData, "test-terraform-github-repository-template")

  assert.Equal(t, "public", repo.GetVisibility())

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

  rootFolder := "../../"
  terraformFolderRelativeToRoot := "examples/complete"
  varFiles := []string{"fixtures.us-east-2.tfvars"}

  tempTestFolder := testStructure.CopyTerraformFolderToTemp(t, rootFolder, terraformFolderRelativeToRoot)

  repositoryName := fmt.Sprintf("terraform-github-repository-test-%s", randID)

  terraformOptions := &terraform.Options{
    // The path to where our Terraform code is located
    TerraformDir: tempTestFolder,
    Upgrade:      true,
    // Variables to pass to our Terraform code using -var-file options
    VarFiles: varFiles,
    Vars: map[string]interface{}{
      "enabled": false,
      "name": repositoryName,
      "visibility": "public",
    },
  }

  // At the end of the test, run `terraform destroy` to clean up any resources that were created
  defer cleanup(t, terraformOptions, tempTestFolder)

  // This will run `terraform init` and `terraform apply` and fail the test if there are any errors
  results := terraform.InitAndApply(t, terraformOptions)

  // Should complete successfully without creating or changing any resources
  assert.Contains(t, results, "Resources: 0 added, 0 changed, 0 destroyed.")
}

func generateRSAKey() (string, error) {
  bitSize := 4096

  // Generate RSA key.
  key, err := rsa.GenerateKey(rand.Reader, bitSize)

  if err != nil {
      return "", err
  }

  // Extract public component.
  pub := key.Public()

	// Extract the public key
	sshPubKey, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}

  return strings.ReplaceAll(string(ssh.MarshalAuthorizedKey(sshPubKey)), "\n", ""), nil
}


func assertVariables(t *testing.T, variables []*github.ActionsVariable, expected map[string]string) {
  actual := make(map[string]string)
  for _, v := range variables {
    actual[v.Name] = v.Value
  }
  assert.Equal(t, len(expected), len(actual))
  for k, v := range expected {
    assert.Equal(t, v, actual[k])
  }
}

func assertSecretNames(t *testing.T, secrets []*github.Secret, expectedNames []string) {
  actualNames := make([]string, len(secrets))
  for i, s := range secrets {
    actualNames[i] = s.Name
  }
  assert.ElementsMatch(t, expectedNames, actualNames)
}
