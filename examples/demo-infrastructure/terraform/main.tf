terraform {
  required_version = ">= 99.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "demo-only"
  secret_key                  = "demo-only"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}

resource "aws_iam_policy" "wildcard_admin" {
  name        = "driftbeacon-demo-wildcard-admin"
  description = "Demo-only policy with intentionally broad permissions."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_s3_bucket" "public_assets" {
  bucket = "driftbeacon-demo-public-assets-do-not-deploy"
}

resource "aws_s3_bucket_public_access_block" "public_assets" {
  bucket = aws_s3_bucket.public_assets.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "public_assets" {
  bucket = aws_s3_bucket.public_assets.id
  acl    = "public-read"
}

resource "aws_ebs_volume" "unencrypted_data" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = false

  tags = {
    Name = "driftbeacon-demo-unencrypted-volume"
  }
}

resource "aws_security_group" "open_ssh" {
  name        = "driftbeacon-demo-open-ssh"
  description = "Demo-only security group with intentionally open SSH."
  vpc_id      = "vpc-00000000000000000"

  ingress {
    description = "Intentionally open SSH for scanner demo."
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Intentionally unrestricted egress for scanner demo."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
