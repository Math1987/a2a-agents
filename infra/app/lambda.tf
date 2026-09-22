data "archive_file" "lambda" {
  type        = "zip"
  source_file = var.bootstrap_path
  output_path = "${path.module}/../../.build/lambda.zip"
}

resource "aws_cloudwatch_log_group" "lambda" {
  for_each          = local.modes
  name              = "/aws/lambda/${var.name}-${each.key}"
  retention_in_days = 14
}

resource "aws_lambda_function" "app" {
  for_each         = local.modes
  function_name    = "${var.name}-${each.key}"
  role             = aws_iam_role.lambda[each.key].arn
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  runtime          = "provided.al2023"
  architectures    = ["x86_64"]
  handler          = "bootstrap"
  memory_size      = each.key == "api" ? 512 : 1024
  timeout          = each.key == "api" ? 30 : 300

  environment {
    variables = merge(var.extra_environment, {
      APP_MODE                               = each.key
      APP_TABLE                              = aws_dynamodb_table.app.name
      APP_QUEUE_URL                          = aws_sqs_queue.tasks.url
      APP_KMS_KEY_ID                         = aws_kms_key.secrets.arn
      APP_PUBLIC_URL                         = local.public_url
      APP_MODEL_ID                           = var.model_id
      APP_COUNT_MODEL_ID                     = var.foundation_model_id
      APP_MONTHLY_BUDGET_MICRO_USD           = tostring(var.monthly_budget_micro_usd)
      APP_INPUT_PRICE_PER_MILLION_MICRO_USD  = tostring(var.input_price_per_million_micro_usd)
      APP_OUTPUT_PRICE_PER_MILLION_MICRO_USD = tostring(var.output_price_per_million_micro_usd)
      RUST_LOG                               = "a2a_agents=info,tower_http=info"
    })
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.common, aws_iam_role_policy.worker]
}

resource "aws_lambda_event_source_mapping" "tasks" {
  event_source_arn        = aws_sqs_queue.tasks.arn
  function_name           = aws_lambda_function.app["worker"].arn
  batch_size              = 1
  function_response_types = ["ReportBatchItemFailures"]
}
