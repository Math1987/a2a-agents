resource "aws_dynamodb_table" "app" {
  name         = var.name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  attribute {
    name = "maintenance_pk"
    type = "S"
  }
  attribute {
    name = "maintenance_due"
    type = "N"
  }
  global_secondary_index {
    name            = "maintenance-index"
    projection_type = "ALL"
    key_schema {
      attribute_name = "maintenance_pk"
      key_type       = "HASH"
    }
    key_schema {
      attribute_name = "maintenance_due"
      key_type       = "RANGE"
    }
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  server_side_encryption {
    enabled = true
  }
}

resource "aws_kms_key" "secrets" {
  description             = "Envelope encryption for a2a-agents connector credentials"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

resource "aws_sqs_queue" "dead_letter" {
  name                      = "${var.name}-dead-letter"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "tasks" {
  name                       = "${var.name}-tasks"
  visibility_timeout_seconds = 1800
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 20
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter.arn
    maxReceiveCount     = 3
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "tasks" {
  queue_url = aws_sqs_queue.dead_letter.url
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.tasks.arn]
  })
}
