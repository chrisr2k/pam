# Deploying PAM on Oracle Cloud Infrastructure (Always Free Tier)

This guide walks through deploying the Privileged Access Manager on Oracle Cloud's Always Free resources:
- **2 AMD VMs** (1 OCPU, 1GB RAM each) OR **1 ARM VM** (up to 4 OCPUs, 24GB RAM)
- **200GB block storage** total
- **10TB outbound data transfer** per month

## Architecture

```
Internet ──► OCI Security List (ports 80/443)
                  │
                  ▼
         Oracle Linux VM (ARM Ampere A1)
                  │
            ┌─────┴─────┐
            │   Caddy   │  ← Auto TLS via Let's Encrypt
            │ (reverse  │
            │  proxy)   │
            └─────┬─────┘
                  │
            ┌─────┴─────┐
            │  Docker   │
            │ Compose   │
            │           │
            │  ┌─────┐  │
            │  │ web │  │  ← Gunicorn + Django
            │  ├─────┤  │
            │  │ db  │  │  ← PostgreSQL 16
            │  ├─────┤  │
            │  │redis│  │  ← Redis 7
            │  ├─────┤  │
            │  │worker│ │  ← Celery worker
            │  ├─────┤  │
            │  │ beat │ │  ← Celery beat
            │  └─────┘  │
            └───────────┘
```

## Prerequisites

1. **Oracle Cloud Account** (sign up at https://signup.cloud.oracle.com)
2. **A domain name** pointed to your VM's public IP
3. **OCI CLI** installed locally (optional, for initial setup)

## Step 1: Create the VM

### Option A: ARM Ampere A1 (Recommended - 4 cores, 24GB RAM free)

1. In OCI Console → Compute → Instances → Create Instance
2. **Name**: `pam-vm`
3. **Image**: Canonical Ubuntu 24.04 (or Oracle Linux 8)
4. **Shape**: Select "Ampere" → VM.Standard.A1.Flex
   - OCPUs: **4** (max free)
   - Memory: **24 GB** (max free)
5. **Networking**: Create a new VCN or use existing
6. **Add SSH key**: Upload your public key
7. **Boot volume**: 100GB (free tier includes 200GB total)

### Option B: Two AMD VMs (1 OCPU, 1GB RAM each)

Create two instances with VM.Standard.E2.1.Micro shape:
- **VM1**: Runs web + db + redis
- **VM2**: Runs celery worker + celery beat

> **Note**: The ARM instance is strongly recommended. It has plenty of resources to run everything on one VM.

## Step 2: Open Firewall Ports

In OCI Console → Networking → Virtual Cloud Networks → Your VCN → Security Lists:

Add ingress rules for:
| Source Type | Source CIDR | Protocol | Port | Description |
|------------|-------------|----------|------|-------------|
| CIDR | 0.0.0.0/0 | TCP | 22 | SSH |
| CIDR | 0.0.0.0/0 | TCP | 80 | HTTP |
| CIDR | 0.0.0.0/0 | TCP | 443 | HTTPS |

Also configure the VM's internal firewall (if using Oracle Linux):

```bash
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

## Step 3: SSH Into the VM

```bash
ssh -i ~/.ssh/your-key opc@<VM_PUBLIC_IP>
```

For Ubuntu, the user is `ubuntu` instead of `opc`.

## Step 4: Install Docker & Docker Compose

```bash
# Update system
sudo dnf update -y   # Oracle Linux
# OR
sudo apt update && sudo apt upgrade -y   # Ubuntu

# Install Docker
curl -fsSL https://get.docker.com | sudo bash

# Add your user to docker group
sudo usermod -aG docker $USER

# Log out and back in for group changes to take effect
exit
# SSH back in

# Verify
docker --version
docker compose version
```

## Step 5: Clone the Repository

```bash
git clone https://github.com/your-org/pam.git
cd pam
```

## Step 6: Configure Environment

```bash
cp .env.example .env
nano .env
```

Set these values:

```ini
# Django
DJANGO_SECRET_KEY=<generate a random 64-char key>
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,your-domain.com

# Database
DATABASE_URL=postgres://pam:pam_password@db:5432/pam

# Redis
REDIS_URL=redis://redis:6379/0

# Entra ID (Azure AD) OIDC
ENTRA_TENANT_ID=your-tenant-id
ENTRA_CLIENT_ID=your-client-id
ENTRA_CLIENT_SECRET=your-client-secret

# AWS
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_SSO_INSTANCE_ARN=arn:aws:sso:::instance/ssoins-xxx

# PAM
PAM_DEFAULT_MAX_HOURS=8
PAM_NOTIFICATION_EMAIL_FROM=noreply@your-domain.com
```

Generate a secure secret key:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Step 7: Configure SSL with Caddy

The project includes a `Caddyfile` and Caddy service in `docker-compose.yml` by default.

Edit the `Caddyfile` to set your domain:

```bash
nano Caddyfile
```

Replace `your-domain.com` with your actual domain:

```caddyfile
your-domain.com {
    reverse_proxy web:8000
    header /static/* {
        Cache-Control "public, max-age=31536000, immutable"
    }
}
```

> **Note**: If you don't have a domain yet, you can comment out the Caddy service in `docker-compose.yml` and access the app directly on port 8080 (e.g., `http://<VM_IP>:8080`).
>
> **Alternative**: If you prefer Nginx, use `nginx:alpine` with certbot for Let's Encrypt.

## Step 8: Start the Application

```bash
# Pull images and start
docker compose up -d

# Check logs
docker compose logs -f

# Verify all services are running
docker compose ps
```

Expected output:
```
NAME                IMAGE               STATUS
pam-db-1            postgres:16-alpine  Up (healthy)
pam-redis-1         redis:7-alpine      Up (healthy)
pam-web-1           pam-web             Up
pam-celery_worker-1 pam-web             Up
pam-celery_beat-1   pam-web             Up
pam-caddy-1         caddy:2-alpine      Up
```

## Step 9: Create Admin User

```bash
# Create a superuser
docker compose exec web python manage.py createsuperuser

# Or use the seed command for demo data
docker compose exec web python manage.py seed_demo
```

## Step 10: Configure DNS

In your domain registrar's DNS settings, create an **A record**:

| Type | Name | Value |
|------|------|-------|
| A | @ | `<VM_PUBLIC_IP>` |
| A | www | `<VM_PUBLIC_IP>` |

Caddy will automatically provision Let's Encrypt certificates once DNS propagates.

## Step 11: Configure Entra ID (Azure AD) OIDC

1. Go to Azure Portal → Entra ID → App Registrations → New Registration
2. Set redirect URI: `https://your-domain.com/accounts/callback/`
3. Note the **Tenant ID**, **Client ID**, and generate a **Client Secret**
4. Update your `.env` file with these values
5. Restart: `docker compose restart web`

## Step 12: Configure AWS Identity Center

1. In AWS Console → IAM Identity Center → Settings → Enable
2. Note your **Instance ARN** (arn:aws:sso:::instance/ssoins-xxx)
3. Create permission sets for the roles you want to manage
4. Update `.env` with your AWS credentials and instance ARN
5. Restart: `docker compose restart web`

## Maintenance

### Backups

```bash
# Backup PostgreSQL database
docker compose exec db pg_dump -U pam pam > pam_backup_$(date +%Y%m%d).sql

# Restore
cat pam_backup.sql | docker compose exec -T db psql -U pam pam
```

### Updates

```bash
# Pull latest code
git pull

# Rebuild and restart
docker compose up -d --build

# Run migrations
docker compose exec web python manage.py migrate
```

### Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f web
docker compose logs -f celery_worker
```

### Monitoring

```bash
# Check resource usage
docker stats

# Check disk usage
df -h

# Check PostgreSQL
docker compose exec db psql -U pam -c "SELECT * FROM pg_stat_activity;"
```

## Troubleshooting

### VM goes down after idle (Oracle free tier behavior)

Oracle may reclaim idle ARM instances. To prevent this:
- Keep the app actively used
- Set up a cron job to hit the health endpoint every hour:

```bash
crontab -e
# Add:
0 * * * * curl -s https://your-domain.com/health/ > /dev/null
```

### Out of memory

The ARM instance with 24GB RAM should handle everything fine. If using AMD instances:
- Reduce Gunicorn workers: change `--workers 4` to `--workers 2` in docker-compose.yml
- Consider running PostgreSQL on a separate AMD instance

### Port 80/443 not accessible

Check both:
1. OCI Security List (VCN → Security Lists → Ingress Rules)
2. VM firewall: `sudo iptables -L` or `sudo firewall-cmd --list-all`

### Caddy can't get certificate

Ensure:
- DNS A record points to your VM's public IP
- Port 80 is accessible (Let's Encrypt uses HTTP-01 challenge)
- Your domain registrar's DNS has propagated (can take a few minutes)

## Cost Breakdown

| Resource | Free Tier Limit | Our Usage | Cost |
|----------|----------------|-----------|------|
| ARM VM | 4 OCPUs / 24GB RAM | 1 VM with 4 OCPU / 24GB | $0 |
| Block Storage | 200GB total | 100GB boot volume | $0 |
| Outbound Data | 10TB/month | Minimal | $0 |
| Domain | Not included | ~$10-15/year | ~$1/mo |
| **Total** | | | **~$1/month** |
