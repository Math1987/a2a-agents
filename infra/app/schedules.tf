resource "aws_scheduler_schedule_group" "maintenance" {
  name = var.name
}

resource "aws_iam_role" "scheduler" {
  name = "${var.name}-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "scheduler.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.aws_account_id }
        ArnEquals    = { "aws:SourceArn" = aws_scheduler_schedule_group.maintenance.arn }
      }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "invoke-worker"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.app["worker"].arn
    }]
  })
}

resource "aws_scheduler_schedule" "maintenance" {
  for_each = {
    oauth_maintenance = "cron(17 3 * * ? *)"
    dispatch_pending  = "rate(5 minutes)"
  }
  name                         = "${var.name}-${replace(each.key, "_", "-")}"
  group_name                   = aws_scheduler_schedule_group.maintenance.name
  schedule_expression          = each.value
  schedule_expression_timezone = "UTC"
  flexible_time_window {
    mode = "OFF"
  }
  target {
    arn      = aws_lambda_function.app["worker"].arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ kind = each.key })
    retry_policy {
      maximum_event_age_in_seconds = 3600
      maximum_retry_attempts       = 2
    }
  }
  depends_on = [aws_iam_role_policy.scheduler]
}
