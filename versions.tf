terraform {
  required_version = ">= 1.0"

  required_providers {
    random = {
      source  = "integrations/github"
      version = ">= 6.6.0"
    }
  }
}
