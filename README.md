# Privileged Access Manager (PAM)

A web-based privileged access management system for **Microsoft Entra ID** (Azure AD) and **AWS Identity Center** (SSO). Built with Django, it provides just-in-time (JIT) elevation, approval workflows, access reviews, and full audit logging.

## Features

- **🔐 Just-in-Time Access** – Request temporary elevation to privileged roles with automatic expiry
- **✅ Approval Workflows** – Multi-level approval chains with email notifications
- **📋 Access Reviews** – Scheduled recertification campaigns with reviewer dashboards
- **📝 Audit Logging** – Immutable audit trail for every access grant, approval, and revocation
- **🔗 Dual Provider Support** – Manage roles in both Entra ID PIM and AWS Identity Center
- **🔔 Notifications** – Email and in-app notifications for requests, approvals, and expirations
- **🏢 Multi-Cloud Ready** – Deploy on Azure, AWS, GCP, OCI, or on-premises

## Quick Start (Local Demo)

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your Entra ID credentials

# 2. Start with Docker Compose
docker compose up -d

# 3. Create admin user
docker compose exec web python manage.py createsuperuser

# 4. Seed demo data (optional)
docker compose exec web python manage.py seed_demo

# 5. Open http://localhost:8080
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Web UI     │────▶│  Django App  │────▶│  PostgreSQL     │
│  (Bootstrap)│     │  (Gunicorn)  │     │  (SQLite dev)   │
└─────────────┘     └──────┬───────┘     └─────────────────┘
                           │
                    ┌──────▼───────┐     ┌─────────────────┐
                    │  Celery      │────▶│  Redis          │
                    │  (Worker)    │     │  (Broker/Backend)│
                    └──────┬───────┘     └─────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
       ┌──────────┐ ┌───────────┐ ┌──────────┐
       │ Entra ID │ │ AWS IAM   │ │ Secrets  │
       │ PIM API  │ │ Identity  │ │ Manager  │
       │          │ │ Center    │ │ (cloud)  │
       └──────────┘ └───────────┘ └──────────┘
```

## App Structure

| App | Purpose |
|-----|---------|
| `accounts` | User model, Entra ID OIDC auth, profiles |
| `roles` | Privileged role definitions, approver assignments |
| `access_requests` | Request/submit/approve/revoke workflows |
| `providers` | Cloud provider integrations (Entra PIM, AWS IC) |
| `tasks` | Celery async provisioning, expiry checks |
| `audit` | Immutable audit log with middleware |
| `reviews` | Access review campaigns and certifications |
| `notifications` | Email and in-app notification system |

## Deployment

See [deploy/README.md](deploy/README.md) for detailed deployment guides:

- **AWS ECS Fargate** – Full Terraform + ECS deployment
- **Azure** – Azure Key Vault + App Service / AKS
- **GCP** – GCP Secret Manager + Cloud Run / GKE
- **OCI** – OCI Vault + OKE / Compute
- **On-Premises** – Docker Compose with Caddy reverse proxy

## Security

- **Secrets** auto-resolved from cloud secrets stores (Azure Key Vault, AWS Secrets Manager, GCP Secret Manager, OCI Vault) with local `.env` fallback
- **Encryption** at rest for sensitive fields (client secrets stored encrypted in DB)
- **HTTPS** enforced via reverse proxy (Caddy auto-TLS or ALB)
- **OIDC** authentication via Entra ID with session management
- **Audit** middleware logs all state-changing operations

## Requirements

- Python 3.11+
- Docker & Docker Compose (for local dev)
- PostgreSQL (production) / SQLite (dev)
- Redis (for Celery)
- Entra ID tenant (for OIDC login)
- AWS account (for Identity Center integration)

## License

MIT
