# Privileged Access Manager (PAM)

A web-based privileged access management system for **Microsoft Entra ID** (Azure AD), **AWS Identity Center** (SSO), and a built-in **digital vault**. Built with Django, it provides just-in-time (JIT) elevation, quorum-based approval workflows, elevation-time MFA, break-glass emergency access, secret checkout with rotation, access reviews, SIEM export, and full audit logging.

> 📖 **Full feature documentation: [docs/FEATURES.md](docs/FEATURES.md)**

## Features

- **🔐 Just-in-Time Access** – Request temporary elevation to privileged roles with automatic expiry (4 redundant expiry mechanisms)
- **🗳️ Quorum Approvals** – Per-role policy: any-one, all-approvers, or fixed N-of-M quorum, with live vote progress
- **📱 Elevation-Time MFA** – TOTP challenges on submit, approve, break-glass, and vault reveal; enrollment required for approvers; lockout after 5 failures
- **🚨 Break-Glass** – One-click emergency access for admins: no approval, short fixed duration, MFA-mandatory, alerts every administrator
- **🗄️ Digital Vault** – Fernet-encrypted secrets with JIT checkout (via the same approval flow), audited one-time reveal, and rotation on check-in — vault-only random by default, or **synced to the real system** via rotation plugins: AWS IAM access keys, Entra app client secrets, SSH, PostgreSQL, MySQL, Windows (WinRM), and generic HTTP webhooks
- **📤 SIEM Export** – Audit events streamed to Splunk HEC / Microsoft Sentinel / generic webhooks within ~45 s
- **🛡️ Threat Analytics** – Five rule-based detections (impossible travel, off-hours elevation, MFA storm, checkout spike, vault reveal spike) with in-app alerts, automatic SIEM export, and email/Slack/Teams fan-out
- **📋 Access Reviews & Role Mining** – Recertification campaigns generated from grant history with usage stats and an "unused access" filter; reviewer decision workflows with automatic completion
- **🔁 SCIM Provisioning** – Entra ID user provisioning/deprovisioning via a SCIM v2 endpoint (soft-deactivate on remove)
- **📝 Audit Logging** – Immutable audit trail for every grant, approval, reveal, rotation, and revocation (~25 event types)
- **🔗 Multi-Provider** – Manage roles in Entra ID PIM, AWS Identity Center, and vault checkouts through one pipeline
- **🔔 Notifications** – Email, Slack, and Teams notifications for requests, approvals, break-glass, and expirations
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

**Note:** approvers and admins must enroll MFA at `/accounts/mfa/setup/`
before they can approve requests or pull break-glass. The seeded demo users
include a vault entry (`Demo-Prod-DB`) whose password auto-rotates whenever
a checkout ends.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Web UI     │────▶│  Django App  │────▶│  PostgreSQL     │
│  (Bootstrap)│     │  (Gunicorn)  │     │  (SQLite dev)   │
└─────────────┘     └──────┬───────┘     └─────────────────┘
                           │
                    ┌──────▼───────┐     ┌─────────────────┐
                    │  Celery      │────▶│  Redis          │
                    │  (Worker/Beat)│    │  (Broker/Backend)│
                    └──────┬───────┘     └─────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
       ┌──────────┐ ┌───────────┐ ┌──────────┐
       │ Entra ID │ │ AWS IAM   │ │ PAM      │
       │ PIM API  │ │ Identity  │ │ Vault    │
       │          │ │ Center    │ │ (Fernet) │
       └──────────┘ └───────────┘ └──────────┘
```

## App Structure

| App | Purpose |
|-----|---------|
| `accounts` | User model, Entra ID OIDC auth, TOTP MFA, profiles |
| `roles` | Privileged role definitions, approver assignments, quorum policy |
| `access_requests` | Request/submit/approve/revoke workflows, break-glass |
| `vault` | Encrypted secrets, JIT checkout, reveal, rotation |
| `providers` | Cloud provider integrations (Entra PIM, AWS IC) |
| `tasks` | Celery async provisioning, expiry checks |
| `audit` | Immutable audit log, SIEM export |
| `reviews` | Access review campaigns and certifications |
| `notifications` | Email, Slack, and Teams notification system |
| `threat` | Rule-based threat detection and alerts |
| `scim` | SCIM v2 endpoint for Entra user provisioning |

## Deployment

See [deploy/README.md](deploy/README.md) for detailed deployment guides:

- **AWS ECS Fargate** – Full Terraform + ECS deployment
- **Azure** – Azure Key Vault + App Service / AKS
- **GCP** – GCP Secret Manager + Cloud Run / GKE
- **OCI** – OCI Vault + OKE / Compute
- **On-Premises** – Docker Compose with Caddy reverse proxy

## Security

- **Secrets** auto-resolved from cloud secrets stores (Azure Key Vault, AWS Secrets Manager, GCP Secret Manager, OCI Vault) with local `.env` fallback
- **Encryption** at rest for sensitive fields (client secrets and TOTP secrets signed; **vault secrets Fernet-AES encrypted** — rotating `SECRET_KEY` destroys them, export first)
- **Elevation-time MFA** on submit/approve/break-glass/reveal with single-use signed challenge tickets and lockout
- **HTTPS** enforced via reverse proxy (Caddy auto-TLS or ALB)
- **OIDC** authentication via Entra ID with session management
- **Audit** middleware logs all state-changing operations, exportable to a SIEM

## Requirements

- Python 3.11+
- Docker & Docker Compose (for local dev)
- PostgreSQL (production) / SQLite (dev)
- Redis (for Celery)
- Entra ID tenant (for OIDC login)
- AWS account (for Identity Center integration)

## License

MIT
