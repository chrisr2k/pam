# PAM Deployment Guide

This directory contains everything needed to deploy the Privileged Access Manager to AWS ECS Fargate.

## Architecture

```
Internet → ALB (HTTPS) → ECS Fargate (web x2) → RDS PostgreSQL
                                        ↕
                              ElastiCache Redis
                                        ↕
                              ECS Fargate (Celery Worker)
```

## Prerequisites

1. **AWS Account** with:
   - VPC with public and private subnets
   - ACM certificate for your domain
   - Route53 hosted zone (optional)
   - RDS PostgreSQL instance (or use AWS RDS)
   - ElastiCache Redis cluster

2. **IAM Permissions**:
   - `AmazonEC2ContainerRegistryFullAccess`
   - `AmazonECS_FullAccess`
   - `IAMFullAccess`
   - `SecretsManagerReadWrite` (for Secrets Manager)
   - `AmazonRoute53FullAccess` (if using Route53)

3. **Tools**:
   - Docker
   - AWS CLI configured with credentials
   - Terraform (or OpenTofu)

## Deployment Steps

### 1. Store Secrets in AWS Secrets Manager

```bash
export DJANGO_SECRET_KEY="your-random-secret-key"
export DATABASE_URL="postgres://user:pass@host:5432/pam"
export REDIS_URL="redis://redis-host:6379/0"
export ENTRA_TENANT_ID="your-tenant-id"
export ENTRA_CLIENT_ID="your-client-id"
export ENTRA_CLIENT_SECRET="your-client-secret"
export AWS_ACCESS_KEY_ID="your-aws-key"
export AWS_SECRET_ACCESS_KEY="your-aws-secret"
export AWS_SSO_INSTANCE_ARN="arn:aws:sso:::instance/ssoins-xxxxx"

./setup-secrets.sh us-east-1
```

### 2. Deploy Infrastructure with Terraform

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your VPC, subnet, and certificate info
tofu init
tofu apply
```

### 3. Build and Push Docker Image

```bash
./build-and-push.sh us-east-1 123456789012
```

### 4. Deploy to ECS

```bash
./deploy-ecs.sh us-east-1 123456789012 pam-cluster
```

### 5. Create Initial Admin User

After deployment, create a superuser via ECS exec:

```bash
aws ecs execute-command \
    --cluster pam-cluster \
    --task $(aws ecs list-tasks --cluster pam-cluster --service-name pam-web --query 'taskArns[0]' --output text) \
    --container web \
    --interactive \
    --command "python manage.py createsuperuser"
```

### 6. Configure Entra ID OIDC

1. Go to `https://pam.example.com/admin/accounts/entrasetup/`
2. Enter your Entra tenant ID, client ID, and client secret
3. The app will generate the callback URL and OIDC configuration

### 7. Add Privileged Roles

1. Go to `https://pam.example.com/admin/roles/privilegedrole/`
2. Add roles for AWS Identity Center permission sets
3. Add roles for Entra ID directory roles
4. Assign approvers to each role

## Demo Mode

The PAM app can run in two demo modes - locally (free) or on ECS (pay-as-you-go).

### Local Demo (Free - $0)

Run entirely on your machine using Docker Compose:

```bash
# 1. Configure your .env file
cp .env.example .env
# Edit .env with your Entra ID credentials

# 2. Start the demo
.\deploy\demo-start.ps1          # PowerShell (Windows)
# or
./deploy/demo-start.sh            # Bash (Linux/Mac/WSL)

# 3. Access locally at http://localhost:8080

# 4. To expose to the internet for demos, install ngrok:
#    https://ngrok.com/download
ngrok http 8080
#    Share the ngrok URL (e.g. https://abc123.ngrok.io)

# 5. Stop when done
.\deploy\demo-stop.ps1            # PowerShell
# or
docker compose down
```

**Cost:** $0 (runs on your machine, ngrok free tier)

### ECS Demo (Scale-to-Zero - ~$2/day when running)

If deployed to ECS, scale services up for demos and down to save costs:

```bash
# Start demo (scales services to 1)
.\deploy\demo-start.ps1 -Mode ecs -Region us-east-1 -AccountId 123456789012 -Cluster pam-cluster

# Stop demo (scales services to 0 - saves ~$2/day)
.\deploy\demo-stop.ps1 -Mode ecs -Region us-east-1 -AccountId 123456789012 -Cluster pam-cluster
```

**Cost when stopped:** ~$54/mo (ALB + RDS + Redis always on)
**Cost during demo:** ~$2/day extra for Fargate

## Local Development

```bash
# Start all services
docker compose up -d

# Create admin user
docker compose exec web python manage.py createsuperuser

# Access at http://localhost:8080
```

## Architecture Details

### Web Tier
- **2x Fargate tasks** (512 CPU, 1024 MB RAM)
- Gunicorn with 4 workers per task
- Health check on `/`

### Background Processing
- **1x Celery Worker** (256 CPU, 512 MB RAM)
- Handles provisioning/deprovisioning
- Auto-expiry scheduling via Celery Beat

### Security
- HTTPS enforced via ALB (HTTP→301→HTTPS)
- Secrets stored in AWS Secrets Manager with automatic rotation support
- ECS tasks run in private subnets
- IAM roles follow least privilege
- Django DEBUG=False in production

### Monitoring
- CloudWatch Log Groups for web and Celery
- Container Insights enabled on ECS cluster
- ALB access logs (enable via Terraform if needed)
