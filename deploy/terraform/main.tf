terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ECR Repository
resource "aws_ecr_repository" "pam" {
  name                 = "pam-web"
  image_tag_mutability = "MUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "pam" {
  name = "pam-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "web" {
  name              = "/ecs/pam-web"
  retention_in_days = 90
}

resource "aws_cloudwatch_log_group" "celery" {
  name              = "/ecs/pam-celery-worker"
  retention_in_days = 90
}

# IAM Roles
resource "aws_iam_role" "ecs_execution" {
  name = "pam-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name = "pam-ecs-execution-secrets-policy"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue"
      ]
      Resource = [
        "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/*"
      ]
    }]
  })
}

resource "aws_iam_role" "ecs_task" {
  name = "pam-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# Task role needs sso-admin and identitystore permissions for AWS Identity Center
resource "aws_iam_role_policy" "ecs_task_sso" {
  name = "pam-ecs-task-sso-policy"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sso-admin:CreateAccountAssignment",
        "sso-admin:DeleteAccountAssignment",
        "sso-admin:ListPermissionSets",
        "sso-admin:DescribePermissionSet",
        "sso-admin:ListInstances",
        "sso-admin:DescribeAccountAssignmentCreationStatus",
        "identitystore:ListUsers",
        "identitystore:DescribeUser"
      ]
      Resource = ["*"]
    }]
  })
}

# ALB
resource "aws_lb" "pam" {
  name               = "pam-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids
}

resource "aws_lb_target_group" "pam" {
  name        = "pam-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }
}

resource "aws_lb_listener" "pam_https" {
  load_balancer_arn = aws_lb.pam.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.pam.arn
  }
}

resource "aws_lb_listener" "pam_http_redirect" {
  load_balancer_arn = aws_lb.pam.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Security Groups
resource "aws_security_group" "alb" {
  name        = "pam-alb-sg"
  description = "PAM ALB security group"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
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

resource "aws_security_group" "ecs_tasks" {
  name        = "pam-ecs-tasks-sg"
  description = "PAM ECS tasks security group"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ECS Service
resource "aws_ecs_service" "web" {
  name            = "pam-web"
  cluster         = aws_ecs_cluster.pam.id
  task_definition = aws_ecs_task_definition.web.arn
  desired_count   = 2
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.pam.arn
    container_name   = "web"
    container_port   = 8000
  }

  depends_on = [aws_lb_listener.pam_https]
}

resource "aws_ecs_service" "celery_worker" {
  name            = "pam-celery-worker"
  cluster         = aws_ecs_cluster.pam.id
  task_definition = aws_ecs_task_definition.celery_worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.ecs_tasks.id]
  }
}

# Task Definitions (using templatefile to inject values)
resource "aws_ecs_task_definition" "web" {
  family                   = "pam-web"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "web"
      image     = "${aws_ecr_repository.pam.repository_url}:latest"
      essential = true
      portMappings = [
        {
          containerPort = 8000
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "DJANGO_DEBUG", value = "False" },
        { name = "DJANGO_ALLOWED_HOSTS", value = var.allowed_hosts },
        { name = "AWS_REGION", value = var.aws_region }
      ]
      secrets = [
        { name = "DJANGO_SECRET_KEY", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/DJANGO_SECRET_KEY" },
        { name = "DATABASE_URL", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/DATABASE_URL" },
        { name = "REDIS_URL", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/REDIS_URL" },
        { name = "ENTRA_TENANT_ID", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/ENTRA_TENANT_ID" },
        { name = "ENTRA_CLIENT_ID", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/ENTRA_CLIENT_ID" },
        { name = "ENTRA_CLIENT_SECRET", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/ENTRA_CLIENT_SECRET" },
        { name = "AWS_ACCESS_KEY_ID", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/AWS_ACCESS_KEY_ID" },
        { name = "AWS_SECRET_ACCESS_KEY", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/AWS_SECRET_ACCESS_KEY" },
        { name = "AWS_SSO_INSTANCE_ARN", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/AWS_SSO_INSTANCE_ARN" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.web.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "pam"
        }
      }
      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8000/ || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])
}

resource "aws_ecs_task_definition" "celery_worker" {
  family                   = "pam-celery-worker"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "celery-worker"
      image     = "${aws_ecr_repository.pam.repository_url}:latest"
      essential = true
      command   = ["celery", "-A", "pam", "worker", "-l", "info"]
      environment = [
        { name = "DJANGO_DEBUG", value = "False" },
        { name = "AWS_REGION", value = var.aws_region }
      ]
      secrets = [
        { name = "DJANGO_SECRET_KEY", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/DJANGO_SECRET_KEY" },
        { name = "DATABASE_URL", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/DATABASE_URL" },
        { name = "REDIS_URL", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/REDIS_URL" },
        { name = "ENTRA_TENANT_ID", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/ENTRA_TENANT_ID" },
        { name = "ENTRA_CLIENT_ID", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/ENTRA_CLIENT_ID" },
        { name = "ENTRA_CLIENT_SECRET", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/ENTRA_CLIENT_SECRET" },
        { name = "AWS_ACCESS_KEY_ID", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/AWS_ACCESS_KEY_ID" },
        { name = "AWS_SECRET_ACCESS_KEY", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/AWS_SECRET_ACCESS_KEY" },
        { name = "AWS_SSO_INSTANCE_ARN", valueFrom = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:pam/AWS_SSO_INSTANCE_ARN" }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.celery.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "pam"
        }
      }
    }
  ])
}

data "aws_caller_identity" "current" {}

# Route53 DNS
resource "aws_route53_record" "pam" {
  count   = var.domain_name != "" ? 1 : 0
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.pam.dns_name
    zone_id                = aws_lb.pam.zone_id
    evaluate_target_health = true
  }
}
