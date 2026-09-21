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

variable "bootstrap_path" {
  description = "Linux x86_64 Lambda executable. Build with scripts/build-lambda.sh first."
  type        = string
  default     = "../../.build/bootstrap"
}

variable "model_id" {
  description = "EU Bedrock inference profile passed to Converse."
  type        = string
  default     = "eu.anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "foundation_model_id" {
  description = "Underlying model for cross-region inference IAM permissions. Must match model_id."
  type        = string
  default     = "anthropic.claude-haiku-4-5-20251001-v1:0"
}

variable "monthly_budget_micro_usd" {
  description = "Shared monthly model-spend cap; not a hard limit on the entire AWS bill."
  type        = number
  default     = 25000000
  validation {
    condition     = var.monthly_budget_micro_usd >= 0 && floor(var.monthly_budget_micro_usd) == var.monthly_budget_micro_usd
    error_message = "The budget must be a non-negative integer in micro USD."
  }
}

variable "input_price_per_million_micro_usd" {
  description = "Conservative EU model input price, in micro USD per million tokens."
  type        = number
  default     = 1100000
}

variable "output_price_per_million_micro_usd" {
  description = "Conservative EU model output price, in micro USD per million tokens."
  type        = number
  default     = 5500000
}

variable "extra_environment" {
  description = "Additional non-secret application configuration (for example explicit model token prices)."
  type        = map(string)
  default     = {}
}
