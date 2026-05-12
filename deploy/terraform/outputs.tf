output "ecr_repository_url" {
  value       = aws_ecr_repository.pam.repository_url
  description = "ECR repository URL for the PAM Docker image"
}

output "ecs_cluster_name" {
  value       = aws_ecs_cluster.pam.name
  description = "ECS cluster name"
}

output "alb_dns_name" {
  value       = aws_lb.pam.dns_name
  description = "ALB DNS name for the PAM app"
}

output "web_service_name" {
  value       = aws_ecs_service.web.name
  description = "ECS service name for the web container"
}

output "celery_service_name" {
  value       = aws_ecs_service.celery_worker.name
  description = "ECS service name for the Celery worker"
}

output "task_role_arn" {
  value       = aws_iam_role.ecs_task.arn
  description = "ARN of the ECS task role (needs SSO Admin permissions)"
}
