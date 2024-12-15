terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "my-terraform-state-bucket-test"
    key            = "terraform/state/terraform.tfstate"
    region         = "us-west-1"
    dynamodb_table = "terraform-lock-table"
    encrypt        = true
  }
}

provider "aws" {
  region = "us-west-1"
}

resource "random_string" "bucket_suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "random_string" "secret_suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "aws_s3_bucket" "config" {
  bucket        = "my-config-bucket-${random_string.bucket_suffix.id}"
  acl           = "private"
  force_destroy = true

  tags = {
    Name = "Config Bucket"
  }
}

resource "aws_iam_policy" "s3_access_policy" {
  name        = "S3AccessPolicy-${random_string.secret_suffix.id}"
  description = "Policy to allow access to S3 config bucket"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Effect   = "Allow"
        Resource = [
          aws_s3_bucket.config.arn,
          "${aws_s3_bucket.config.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role" "ec2_role" {
  name = "ec2-instance-role-${random_string.secret_suffix.id}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_policy_attachment" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_access_policy.arn
}

resource "aws_security_group" "ec2_sg" {
  name_prefix = "ec2-sg-"
  description = "Allow HTTPS and SSH"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "ec2" {
  ami           = "ami-055e3d4f0bbeb5878"
  instance_type = "t2.micro"
  key_name      = "my-key-pair"
  security_groups = [aws_security_group.ec2_sg.name]

  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name

  user_data = <<-EOT
              #!/bin/bash
              yum update -y
              yum install -y nginx aws-cli
              aws s3 cp s3://${aws_s3_bucket.config.bucket}/nginx.conf /etc/nginx/nginx.conf
              systemctl start nginx
              EOT

  tags = {
    Name = "Terraform EC2 Instance"
  }
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2-instance-profile-${random_string.secret_suffix.id}"
  role = aws_iam_role.ec2_role.name
}

resource "aws_secretsmanager_secret" "db_secret" {
  name = "database-credentials-${random_string.secret_suffix.id}"
}

resource "aws_secretsmanager_secret_version" "db_secret_version" {
  secret_id = aws_secretsmanager_secret.db_secret.id

  secret_string = jsonencode({
    DATABASE_USERNAME = var.database_username,
    DATABASE_PASSWORD = var.database_password
  })
}

resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 2048

  private_key_pem = var.ssh_private_key
}

variable "database_username" {
  type        = string
  description = "Database username"
}

variable "database_password" {
  type        = string
  description = "Database password"
}

variable "ssh_private_key" {
  type        = string
  description = "SSH private key used for deployments"
  default     = "${env.SSH_PRIVATE_KEY}"
}

output "ec2_public_ip" {
  value = aws_instance.ec2.public_ip
}

output "s3_bucket_name" {
  value = aws_s3_bucket.config.bucket
}
