# Start PAM demo environment
# Usage: .\demo-start.ps1 [-Mode local|ecs] [-Region us-east-1] [-AccountId 123456789012] [-Cluster pam-cluster]

param(
    [ValidateSet('local', 'ecs')]
    [string]$Mode = 'local',
    [string]$Region = 'us-east-1',
    [string]$AccountId = '',
    [string]$Cluster = 'pam-cluster'
)

if ($Mode -eq 'ecs') {
    if (-not $AccountId) {
        Write-Error "Usage: .\demo-start.ps1 -Mode ecs -Region <region> -AccountId <account-id> -Cluster <cluster-name>"
        exit 1
    }

    Write-Host "=== Starting PAM Demo on ECS ===" -ForegroundColor Green

    # Scale web service to 1
    Write-Host "Scaling web service to 1..."
    aws ecs update-service --cluster $Cluster --service pam-web --desired-count 1 --region $Region | Out-Null

    # Scale celery worker to 1
    Write-Host "Scaling celery worker to 1..."
    aws ecs update-service --cluster $Cluster --service pam-celery-worker --desired-count 1 --region $Region | Out-Null

    Write-Host "Waiting for services to stabilize..."
    aws ecs wait services-stable --cluster $Cluster --services pam-web pam-celery-worker --region $Region

    # Get the ALB URL
    $AlbDns = aws elbv2 describe-load-balancers --names pam-alb --region $Region --query 'LoadBalancers[0].DNSName' --output text

    Write-Host "`n=== PAM Demo is LIVE ===" -ForegroundColor Green
    Write-Host "URL: https://$AlbDns" -ForegroundColor Cyan
    Write-Host "`nTo stop: .\demo-stop.ps1 -Mode ecs -Region $Region -AccountId $AccountId -Cluster $Cluster" -ForegroundColor Yellow

} else {
    # Local mode - use docker-compose
    Write-Host "=== Starting PAM Demo Locally ===" -ForegroundColor Green

    $pamDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
    Set-Location $pamDir

    # Check if .env exists
    if (-not (Test-Path .env)) {
        Write-Error "No .env file found. Copy .env.example to .env and configure it."
        Write-Host "  copy .env.example .env" -ForegroundColor Yellow
        Write-Host "  # Then edit .env with your Entra ID credentials" -ForegroundColor Yellow
        exit 1
    }

    # Start services
    Write-Host "Starting Docker Compose services..."
    docker compose up -d

    Write-Host "Waiting for web service to be ready..."
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $response = Invoke-WebRequest -Uri http://localhost:8080/ -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) { break }
        } catch {
            # Not ready yet
        }
        Start-Sleep -Seconds 2
    }

    Write-Host "`n=== PAM Demo is running locally ===" -ForegroundColor Green
    Write-Host "Local URL: http://localhost:8080" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Demo accounts (created automatically on first run):" -ForegroundColor Yellow
    Write-Host "  Admin:     admin / admin123" -ForegroundColor Yellow
    Write-Host "  Approver:  approver / approver123" -ForegroundColor Yellow
    Write-Host "  Requester: requester / requester123" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To expose to the internet, install ngrok from https://ngrok.com and run:" -ForegroundColor Yellow
    Write-Host "  ngrok http 8080" -ForegroundColor Yellow
    Write-Host "`nTo stop: docker compose down" -ForegroundColor Yellow
}
