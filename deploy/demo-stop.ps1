# Stop PAM demo environment
# Usage: .\demo-stop.ps1 [-Mode local|ecs] [-Region us-east-1] [-AccountId 123456789012] [-Cluster pam-cluster]

param(
    [ValidateSet('local', 'ecs')]
    [string]$Mode = 'local',
    [string]$Region = 'us-east-1',
    [string]$AccountId = '',
    [string]$Cluster = 'pam-cluster'
)

if ($Mode -eq 'ecs') {
    if (-not $AccountId) {
        Write-Error "Usage: .\demo-stop.ps1 -Mode ecs -Region <region> -AccountId <account-id> -Cluster <cluster-name>"
        exit 1
    }

    Write-Host "=== Stopping PAM Demo on ECS ===" -ForegroundColor Yellow

    # Scale web service to 0
    Write-Host "Scaling web service to 0..."
    aws ecs update-service --cluster $Cluster --service pam-web --desired-count 0 --region $Region | Out-Null

    # Scale celery worker to 0
    Write-Host "Scaling celery worker to 0..."
    aws ecs update-service --cluster $Cluster --service pam-celery-worker --desired-count 0 --region $Region | Out-Null

    Write-Host "`n=== PAM Demo stopped ===" -ForegroundColor Yellow
    Write-Host "ECS services scaled to 0. No Fargate costs." -ForegroundColor Green
    Write-Host "ALB, RDS, and Redis are still running (baseline ~$54/mo)." -ForegroundColor Gray
    Write-Host "`nTo restart: .\demo-start.ps1 -Mode ecs -Region $Region -AccountId $AccountId -Cluster $Cluster" -ForegroundColor Cyan

} else {
    # Local mode - stop docker-compose
    Write-Host "=== Stopping PAM Demo Locally ===" -ForegroundColor Yellow

    $pamDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
    Set-Location $pamDir

    Write-Host "Stopping Docker Compose services..."
    docker compose down

    Write-Host "`n=== PAM Demo stopped ===" -ForegroundColor Yellow
    Write-Host "All containers stopped and removed." -ForegroundColor Green
    Write-Host "`nTo restart: .\demo-start.ps1" -ForegroundColor Cyan
}
