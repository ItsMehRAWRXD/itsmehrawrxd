@echo off
echo 🚀 Setting up Ollama API Service...

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not installed. Please install Docker first.
    pause
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

REM Create logs directory
if not exist logs mkdir logs

REM Set up environment variables
echo 📝 Setting up environment variables...
if not exist .env (
    (
        echo # Ollama Service Configuration
        echo OLLAMA_URL=http://host.docker.internal:11434
        echo YOUR_API_KEY=your-secret-key-here
        echo DEFAULT_MODEL=llama3
        echo DEBUG=false
        echo PORT=5000
    ) > .env
    echo ✅ Created .env file with default settings
    echo ⚠️  Please update the YOUR_API_KEY in .env file for security
) else (
    echo ✅ .env file already exists
)

REM Build and start the service
echo 🔨 Building and starting the service...
docker-compose up --build -d

REM Wait for service to be ready
echo ⏳ Waiting for service to be ready...
timeout /t 10 /nobreak >nul

REM Check if service is running
curl -f http://localhost:5000/api/health >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Service is running successfully!
    echo 🌐 API available at: http://localhost:5000
    echo 📊 Health check: http://localhost:5000/api/health
    echo 📋 Models list: http://localhost:5000/api/models
) else (
    echo ❌ Service failed to start. Check logs with: docker-compose logs
    pause
    exit /b 1
)

echo.
echo 🎉 Setup complete! Your Ollama API service is ready.
echo.
echo Next steps:
echo 1. Update the API key in .env file
echo 2. Configure your browser extension with: http://localhost:5000
echo 3. Make sure Ollama is running on your system
echo.
echo Useful commands:
echo   View logs: docker-compose logs -f
echo   Stop service: docker-compose down
echo   Restart service: docker-compose restart
echo   Update service: docker-compose up --build -d
echo.
pause
