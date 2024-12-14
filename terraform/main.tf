provider "aws" {
  region = "us-east-2"
}

# Генерация случайного суффикса для уникальных имен
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
  numeric  = true
}

resource "random_string" "secret_suffix" {
  length  = 8
  special = false
  upper   = false
  numeric  = true
}

# EC2 instance to host Nginx
resource "aws_instance" "container_instance" {
  ami           = "ami-0453ec754f44f9a4a"  # Use a suitable AMI for EC2 instance
  instance_type = "t3.micro"               # Instance type

  security_groups = [aws_security_group.container_sg.name]
  iam_instance_profile = aws_iam_instance_profile.container_iam_profile.name

  user_data = <<-EOF
              #!/bin/bash
              # Install Nginx
              yum update -y
              yum install -y nginx
              # Set up SSH key for access
              mkdir -p /home/ec2-user/.ssh
              echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDfsTTL6TCKHvRu22IKMPE7MMl8axo9N2U6FNbivFC547DNwrVetWmeWRwYnvee2yNJGK1hbHZTWRT91cBfC40GQzJDRyun9uii8NTSI62U4VgmjjAk4E+pWjZJH3ePTrbaQL2X+LG0NkV+29QHmKvEu9FrtucCcnn3jN0joTwJt27I9+zYs56d7R8VZpYEYXnE6gqbYnX9XResxOodV2ihfrtMGWOr1/6pbBtR7OkY4AiLkyPzzmuGej2hydEMxdNnHiIPFViMMtBxANVtfFDRC3YCG6gGEn1ePguR/vBSNXc0078RJ9xOayH5fNinqLm365OSSZ2oowM5VtRpCWqHlhFNsrIW6ZjkJUrAotDBwUtfkN8iyEa2JSlumIS2+TRidaCx7MTUG4hEuLflZcz2CyAPegbIazy/8V+uLv5u+sd24JljFjjnfnpv+K80ezJWKzqlZjFN2t/xB8KbMDrL5lBFxxwr2o2dMYJn+uTeqW0HJI1zf17HKhcYBZgM1KhyiGxa2nq9NIzEjVwdI7bMJ4ER9sxnZmuItnVGx7G/ncJxxHpPCCjK48hSHyb9d11SPROBwg8QHoK+4Ba4tNldXky+5NbDrJEYFypiWYBkxnxgJoEU9Bj8LKnD4NgF0Bgjjo7BcLXsUlYVIJuZc1E/Ef1JNC/ZUQ/ZPgwZ6qW8Mw== ahmad@DESKTOP-BVAMA07" >> /home/ec2-user/.ssh/authorized_keys
              chmod 600 /home/ec2-user/.ssh/authorized_keys
              chown -R ec2-user:ec2-user /home/ec2-user/.ssh
              # Download Nginx configuration from S3
              aws s3 cp s3://my-config-bucket-${random_string.bucket_suffix.id}/nginx.conf /etc/nginx/nginx.conf
              # Start Nginx service
              systemctl start nginx
              systemctl enable nginx
              # Configure SSH to listen on port 443
              sed -i 's/#Port 22/Port 443/' /etc/ssh/sshd_config
              systemctl restart sshd
              EOF

  tags = {
    Name = "ContainerInstance"
  }
}

# Security group for HTTPS access
resource "aws_security_group" "container_sg" {
  name_prefix = "container_sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow from anywhere
  }

  # Deny all other inbound traffic (default action)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM role for EC2 instance
resource "aws_iam_role" "container_iam_role" {
  name = "container_iam_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

# IAM instance profile
resource "aws_iam_instance_profile" "container_iam_profile" {
  name = "container_iam_profile"
  role = aws_iam_role.container_iam_role.name
}

# IAM policy for S3 and Secrets Manager access
resource "aws_iam_policy" "access_policy" {
  name        = "AccessPolicy"
  description = "Allow access to S3 and Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = [
          "secretsmanager:GetSecretValue",
          "s3:GetObject"
        ]
        Effect    = "Allow"
        Resource  = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "access_policy_attachment" {
  policy_arn = aws_iam_policy.access_policy.arn
  role       = aws_iam_role.container_iam_role.name
}

# Store environment variables in Secrets Manager
resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "db_credentials_${random_string.secret_suffix.id}"
  recovery_window_in_days = 0
}

# Secrets Manager secret version
resource "aws_secretsmanager_secret_version" "secret_version" {
  secret_id     = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    DATABASE_USERNAME = "myuser"
    DATABASE_PASSWORD = "mypassword"
  })
}

# S3 bucket for Nginx config
resource "aws_s3_bucket" "nginx_config_bucket" {
  bucket = "my-config-bucket-${random_string.bucket_suffix.id}"
}

resource "aws_s3_bucket" "terraform_state" {
  provider = aws
  bucket = "my-terraform-state-bucket"
  acl    = "private"
}

resource "aws_dynamodb_table" "terraform_locks" {
  name         = "terraform-lock-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"  # Указываем LockID как ключ

  attribute {
    name = "LockID"
    type = "S"  # Тип строки (String)
  }
}



# Upload Nginx configuration file to S3
resource "aws_s3_bucket_object" "nginx_config" {
  bucket = aws_s3_bucket.nginx_config_bucket.bucket
  key    = "nginx.conf"
  source = "nginx.conf"
  acl    = "private"
}

output "ec2_public_ip" {
  value = aws_instance.container_instance.public_ip
}

output "s3_bucket_name" {
  value = aws_s3_bucket.nginx_config_bucket.bucket
}

output "secret_name" {
  value = aws_secretsmanager_secret.db_credentials.name
}