terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.64" }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]
  default_tags {
    tags = { Project = "a2a-agents", Environment = "poc", ManagedBy = "terraform" }
  }
}

variable "aws_region" {
  type    = string
  default = "eu-west-3"
}
variable "aws_account_id" {
  type    = string
  default = "128066560720"
}
variable "name" {
  type    = string
  default = "a2a-agents-poc"
}
variable "github_oidc_subject" {
  description = "Exact subject claim for Math1987/a2a-agents main, including immutable IDs if GitHub uses them."
  type        = string
  default     = "repo:Math1987@55652304/a2a-agents@1379233470:ref:refs/heads/main"
  validation {
    condition     = startswith(var.github_oidc_subject, "repo:Math1987") && endswith(var.github_oidc_subject, ":ref:refs/heads/main") && !strcontains(var.github_oidc_subject, "*")
    error_message = "Use the exact main branch OIDC subject, without wildcards."
  }
}

locals {
  state_bucket = "aithos-a2a-agents-tfstate-${var.aws_account_id}-${var.aws_region}"
}

# The account already has this provider. Reference it; do not alter its trust configuration.
data "aws_iam_openid_connect_provider" "github" {
  arn = "arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com"
}

resource "aws_s3_bucket" "state" {
  bucket = local.state_bucket
  lifecycle {
    prevent_destroy = true
  }
}
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_iam_role" "deploy" {
  name                 = "${var.name}-github-deploy"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = var.github_oidc_subject
        }
      }
    }]
  })
}

# Deliberately a code-deployment role. Infrastructure updates require an operator's AWS identity.
# A compromised workflow cannot change IAM roles, read DynamoDB, or decrypt connector tokens.
resource "aws_iam_role_policy" "deploy" {
  name = "update-application-code"
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["lambda:UpdateFunctionCode", "lambda:GetFunction", "lambda:GetFunctionConfiguration"]
      Resource = [
        "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:${var.name}-api",
        "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:${var.name}-worker"
      ]
    }]
  })
}

output "state_bucket" {
  value = aws_s3_bucket.state.id
}
output "deployment_role_arn" {
  value = aws_iam_role.deploy.arn
}
