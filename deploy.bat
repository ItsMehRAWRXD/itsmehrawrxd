@echo off
echo RawrZApp Digital Ocean Deployment
echo ==================================

REM Check if required files exist
if not exist ".do\app.yaml" (
    echo Error: .do\app.yaml not found
    exit /b 1
)

if not exist "package.json" (
    echo Error: package.json not found
    exit /b 1
)

echo Configuration files found

REM Check Node.js version
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Node.js not found
    exit /b 1
) else (
    for /f "tokens=*" %%i in ('node --version') do echo Node.js version: %%i
)

REM Install dependencies
echo Installing dependencies...
npm install

if %errorlevel% neq 0 (
    echo Error: Failed to install dependencies
    exit /b 1
) else (
    echo Dependencies installed successfully
)

REM Test the application
echo Testing application...
start /b npm start
timeout /t 5 /nobreak >nul

REM Check if app is running
curl -f http://localhost:8080/health >nul 2>&1
if %errorlevel% equ 0 (
    echo Application is running and healthy
    taskkill /f /im node.exe >nul 2>&1
) else (
    echo Error: Application health check failed
    taskkill /f /im node.exe >nul 2>&1
    exit /b 1
)

echo.
echo RawrZApp is ready for deployment!
echo.
echo Next steps:
echo 1. Push your code to GitHub repository: ItsMehRAWRXD/itsmehrawrxd
echo 2. Go to Digital Ocean App Platform: https://cloud.digitalocean.com/apps
echo 3. Create new app and connect your GitHub repository
echo 4. Use the configuration from .do\app.yaml
echo 5. Deploy and enjoy your $5/month RawrZApp!
echo.
echo See DEPLOYMENT.md for detailed instructions
pause
