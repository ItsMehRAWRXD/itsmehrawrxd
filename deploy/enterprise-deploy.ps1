# RawrZ Enterprise Deployment Script for Windows
param(
    [string]$Environment = "production",
    [string]$Domain = "localhost",
    [string]$Email = "admin@rawrz.com"
)

Write-Host "Starting RawrZ Enterprise Deployment..." -ForegroundColor Blue

# Configuration
Write-Host "Deployment Configuration:" -ForegroundColor Blue
Write-Host "Environment: $Environment"
Write-Host "Domain: $Domain"
Write-Host "Email: $Email"

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker is not installed" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
    Write-Host "Docker Compose is not installed" -ForegroundColor Red
    exit 1
}

Write-Host "Prerequisites check passed" -ForegroundColor Green

# Create environment file
Write-Host "Creating environment configuration..." -ForegroundColor Yellow

$postgresPassword = [System.Web.Security.Membership]::GeneratePassword(32, 0)
$redisPassword = [System.Web.Security.Membership]::GeneratePassword(32, 0)
$grafanaPassword = [System.Web.Security.Membership]::GeneratePassword(16, 0)

$envContent = @"
# RawrZ Enterprise Environment
NODE_ENV=production
DOMAIN=$Domain
EMAIL=$Email

# Database
POSTGRES_PASSWORD=$postgresPassword
POSTGRES_DB=rawrz_enterprise
POSTGRES_USER=rawrz

# Redis
REDIS_PASSWORD=$redisPassword

# Monitoring
GRAFANA_PASSWORD=$grafanaPassword

# SSL
SSL_EMAIL=$Email
"@

$envContent | Out-File -FilePath ".env" -Encoding UTF8

Write-Host "Environment file created" -ForegroundColor Green

# Generate SSL certificates
Write-Host "Generating SSL certificates..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "nginx\ssl" | Out-Null

# Create self-signed certificate
$cert = New-SelfSignedCertificate -DnsName $Domain -CertStoreLocation "Cert:\CurrentUser\My"
$certPath = "Cert:\CurrentUser\My\$($cert.Thumbprint)"
$pwd = ConvertTo-SecureString -String "password" -Force -AsPlainText
Export-PfxCertificate -Cert $certPath -FilePath "nginx\ssl\cert.pfx" -Password $pwd

# Convert to PEM format (requires OpenSSL or alternative)
Write-Host "Note: Convert cert.pfx to PEM format for production use" -ForegroundColor Yellow

Write-Host "SSL certificates generated" -ForegroundColor Green

# Start services
Write-Host "Starting enterprise services..." -ForegroundColor Yellow
docker-compose -f docker-compose.enterprise.yml up -d

# Wait for services to be ready
Write-Host "Waiting for services to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Health check
Write-Host "Performing health checks..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/health" -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Host "RawrZ application is healthy" -ForegroundColor Green
    } else {
        Write-Host "RawrZ application health check failed" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "RawrZ application health check failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Display deployment information
Write-Host "RawrZ Enterprise Deployment Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Service URLs:" -ForegroundColor Blue
Write-Host "RawrZ Application: https://$Domain"
Write-Host "Grafana Dashboard: http://$Domain:3000"
Write-Host "Prometheus Metrics: http://$Domain:9090"
Write-Host "Kibana Logs: http://$Domain:5601"
Write-Host ""
Write-Host "Default Credentials:" -ForegroundColor Blue
Write-Host "Grafana Admin: admin / $grafanaPassword"
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Configure your domain DNS to point to this server"
Write-Host "2. Update SSL certificates with Let's Encrypt if needed"
Write-Host "3. Configure monitoring alerts in Grafana"
Write-Host "4. Set up backup schedules"
Write-Host "5. Review security settings"
Write-Host ""
Write-Host "RawrZ Enterprise is ready for production use!" -ForegroundColor Green
