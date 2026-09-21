output "api_url" {
  value = aws_apigatewayv2_api.api.api_endpoint
}
output "table_name" {
  value = aws_dynamodb_table.app.name
}
output "queue_url" {
  value = aws_sqs_queue.tasks.url
}
output "dead_letter_queue_url" {
  value = aws_sqs_queue.dead_letter.url
}
output "kms_key_id" {
  value = aws_kms_key.secrets.arn
}
output "lambda_functions" {
  value = { for mode, fn in aws_lambda_function.app : mode => fn.function_name }
}
