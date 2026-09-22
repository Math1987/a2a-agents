output "api_url" {
  description = "Canonical API URL; also used as the OAuth callback origin."
  value       = local.public_url
  depends_on  = [aws_apigatewayv2_api_mapping.api, aws_route53_record.api]
}
output "execute_api_url" {
  description = "Underlying API Gateway endpoint for diagnostics; OAuth uses api_url."
  value       = aws_apigatewayv2_api.api.api_endpoint
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
