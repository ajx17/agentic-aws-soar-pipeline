provider "aws" {
  region = "us-east-1"
}

# 1. The Vulnerable Security Group (Open SSH)
resource "aws_security_group" "vulnerable_sg" {
  name        = "agentic_lab_open_sg"
  description = "Allows SSH from anywhere"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Massive red flag
  }
}

# 2. The Vulnerable S3 Bucket (Publicly Readable & Listable)
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "agentic-lab-exposed-bucket-${random_id.bucket_id.hex}"
}

resource "random_id" "bucket_id" {
  byte_length = 4
}

resource "aws_s3_bucket_public_access_block" "public_access" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# 3. The Vulnerable Bucket Policy (Fixed Race Condition & List access)
resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  
  # This tells Terraform to wait for the block settings to apply first
  depends_on = [aws_s3_bucket_public_access_block.public_access]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadAndList"
        Effect    = "Allow"
        Principal = "*"
        Action    = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource  = [
          "${aws_s3_bucket.vulnerable_bucket.arn}",
          "${aws_s3_bucket.vulnerable_bucket.arn}/*"
        ]
      },
    ]
  })
}
