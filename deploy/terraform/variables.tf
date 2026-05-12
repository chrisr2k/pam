variable "aws_region" {
  type        = string
  description = "AWS region for deployment"
  default     = "us-east-1"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for the ECS cluster and ALB"
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "List of public subnet IDs for the ALB"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "List of private subnet IDs for ECS tasks"
}

variable "certificate_arn" {
  type        = string
  description = "ARN of the ACM certificate for HTTPS"
}

variable "allowed_hosts" {
  type        = string
  description = "Comma-separated allowed hosts for Django"
  default     = "pam.example.com,localhost"
}

variable "domain_name" {
  type        = string
  description = "Domain name for the PAM app (leave empty if not using Route53)"
  default     = ""
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 hosted zone ID (required if domain_name is set)"
  default     = ""
}
