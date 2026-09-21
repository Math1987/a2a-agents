terraform {
  required_version = ">= 1.10, < 2.0"
  backend "s3" {
    key          = "app/terraform.tfstate"
    region       = "eu-west-3"
    encrypt      = true
    use_lockfile = true
  }
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 6.64" }
    archive = { source = "hashicorp/archive", version = "~> 2.8" }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]
  default_tags {
    tags = { Project = "a2a-agents", Environment = "poc", ManagedBy = "terraform" }
  }
}

data "aws_partition" "current" {}
