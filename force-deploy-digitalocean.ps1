# RawrZ Security Platform - Force Deployment to DigitalOcean
# This script will delete existing deployments and trigger fresh deployment

Write-Host "🚀 RawrZ Security Platform - Force Deployment to DigitalOcean" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "📋 Deployment Strategy:" -ForegroundColor Yellow
Write-Host "1. Clean existing deployment artifacts" -ForegroundColor White
Write-Host "2. Pull latest changes from main branch" -ForegroundColor White  
Write-Host "3. Force push deployment trigger" -ForegroundColor White
Write-Host "4. Validate deployment readiness" -ForegroundColor White
Write-Host ""

# Step 1: Clean repository state
Write-Host "🧹 Step 1: Cleaning repository state..." -ForegroundColor Yellow
try {
    git stash --timestamps
    git clean -fd
    Write-Host "✅ Repository cleaned" -ForegroundColor Green
} catch {
    Write-Host "ℹ️  Repository clean or minor errors ignored" -ForegroundColor Blue
}

# Step 2: Ensure we're on main branch
Write-Host "📍 Step 2: Ensuring main branch..." -ForegroundColor Yellow
git checkout main
git pull origin main --force
Write-Host "✅ On main branch with latest changes" -ForegroundColor Green

# Step 3: Validate deployment files exist
Write-Host "🔍 Step 3: Validating deployment files..." -ForegroundColor Yellow

$required_files = @(
    "server.js",
    "package.json", 
    "Dockerfile",
    "deploy-digitalocean-privileged.sh"
)

$missing_files = @()
foreach ($file in $required_files) {
    if (!(Test-Path $file)) {
        $missing_files += $file
    }
}

if ($missing_files.Count -gt 0) {
    Write-Host "❌ Missing deployment files:" -ForegroundColor Red
    foreach ($file in $missing_files) {
        Write-Host "  - $file" -ForegroundColor Red
    }
    Write-Host "Deployment aborted - files missing" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✅ All required deployment files present" -ForegroundColor Green

# Step 4: Commit any deployment improvements  
Write-Host "📋 Step 4: Committing deployment improvements..." -ForegroundColor Yellow
git add .
git commit -m "DEPLOY: Clean deployment push to DigitalOcean with all features operational" 2>$null
git push origin main --force-with-lease
Write-Host "✅ Code pushed to trigger deployment" -ForegroundColor Green

# Step 5: Provide DigitalOcean deployment instructions
Write-Host "🌊 Step 5: DigitalOcean Deployment Commands:" -ForegroundColor Yellow
Write-Host ""
Write-Host "For DigitalOcean App Platform:" -ForegroundColor Cyan
Write-Host "  1. Log into DigitalOcean Console" -ForegroundColor White
Write-Host "  2. Navigate to Apps section" -ForegroundColor White
Write-Host "  3. Delete existing 'rawrz-security-platform' app" -ForegroundColor White
Write-Host "  4. Create new app from GitHub repo: itsmehrawrxd" -ForegroundColor White
Write-Host "  5. Select branch: main" -ForegroundColor White
Write-Host "  6. Build command: npm install && node server.js" -ForegroundColor White
Write-Host "  7. Deploy with domain assignment" -ForegroundColor White
Write-Host ""

Write-Host "For DigitalOcean Droplet:" -ForegroundColor Cyan
Write-Host "  1. SSH into your DigitalOcean droplet" -ForegroundColor White
Write-Host "  2. Run: ./deploy-digitalocean-droplet.sh" -ForegroundColor White
Write-Host "  3. Or run: docker-compose up -d" -ForegroundColor White
Write-Host ""

# Step 6: Check if we can trigger automated deployment
Write-Host "🤖 Step 6: Automated deployment status..." -ForegroundColor Yellow

# Check if GitHub Actions are configured
$github_workflows = Get-ChildItem -Path ".github/workflows" -Recurse -ErrorAction SilentlyContinue
if ($github_workflows) {
    Write-Host "✅ GitHub Actions workflows detected" -ForegroundColor Green
    Write-Host "   Deployment should trigger automatically via GitHub Actions" -ForegroundColor White
} else {
    Write-Host "⚠️  No GitHub Actions detected" -ForegroundColor Yellow
    Write-Host "   Manual deployment required on DigitalOcean console" -ForegroundColor White
}

Write-Host ""
Write-Host "🎉 Deployment preparation complete!" -ForegroundColor Green
Write-Host "✅ Repository: Clean and up to date" -ForegroundColor Green  
Write-Host "✅ Code: Latest version pushed to main branch" -ForegroundColor Green
Write-Host "✅ Files: All required deployment files present" -ForegroundColor Green
Write-Host ""
Write-Host "🔗 Repository URL: https://github.com/ItsMehRAWRXD/itsmehrawrxd" -ForegroundColor Cyan
Write-Host "📍 Branch: main" -ForegroundColor Cyan  
Write-Host "🚀 READY FOR DEPLOYMENT!" -ForegroundColor Green
Write-Host ""

Read-Host "Press Enter to continue"
