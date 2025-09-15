@echo off
REM RawrZ Security Platform Deployment Script for Windows
REM This script handles deployment of the RawrZ Security Platform

setlocal enabledelayedexpansion

REM Configuration
set PROJECT_NAME=rawrz-security-platform
set DOCKER_COMPOSE_FILE=docker-compose.yml
set ENV_FILE=.env

REM Functions
:log_info
echo [INFO] %~1
goto :eof

:log_success
echo [SUCCESS] %~1
goto :eof

:log_warning
echo [WARNING] %~1
goto :eof

:log_error
echo [ERROR] %~1
goto :eof

REM Check if Docker is installed
:check_docker
docker --version >nul 2>&1
if errorlevel 1 (
    call :log_error "Docker is not installed. Please install Docker Desktop first."
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    call :log_error "Docker Compose is not installed. Please install Docker Compose first."
    exit /b 1
)

call :log_success "Docker and Docker Compose are installed"
goto :eof

REM Check if .env file exists
:check_env_file
if not exist "%ENV_FILE%" (
    call :log_warning ".env file not found. Creating from example..."
    if exist "env.example" (
        copy env.example .env >nul
        call :log_warning "Please edit .env file with your configuration before continuing"
        call :log_warning "Press any key to continue after editing .env file..."
        pause >nul
    ) else (
        call :log_error "env.example file not found. Please create .env file manually."
        exit /b 1
    )
)
call :log_success "Environment file found"
goto :eof

REM Create necessary directories
:create_directories
call :log_info "Creating necessary directories..."
if not exist "data" mkdir data
if not exist "uploads" mkdir uploads
if not exist "logs" mkdir logs
if not exist "ssl" mkdir ssl
call :log_success "Directories created"
goto :eof

REM Generate SSL certificates (self-signed for development)
:generate_ssl_certificates
if not exist "ssl\cert.pem" (
    call :log_info "Generating self-signed SSL certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout ssl\key.pem -out ssl\cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" >nul 2>&1
    if errorlevel 1 (
        call :log_warning "OpenSSL not found. SSL certificates will need to be generated manually."
    ) else (
        call :log_success "SSL certificates generated"
    )
) else (
    call :log_success "SSL certificates already exist"
)
goto :eof

REM Build and start services
:deploy_services
call :log_info "Building and starting services..."
docker-compose -f %DOCKER_COMPOSE_FILE% down --remove-orphans
docker-compose -f %DOCKER_COMPOSE_FILE% build --no-cache
docker-compose -f %DOCKER_COMPOSE_FILE% up -d
call :log_success "Services deployed"
goto :eof

REM Wait for services to be ready
:wait_for_services
call :log_info "Waiting for services to be ready..."

set /a max_attempts=30
set /a attempt=1

:wait_loop
curl -f http://localhost:8080/api/status >nul 2>&1
if not errorlevel 1 (
    call :log_success "RawrZ Security Platform is ready"
    goto :eof
)

if %attempt% equ %max_attempts% (
    call :log_error "RawrZ Security Platform failed to start within timeout"
    exit /b 1
)

call :log_info "Waiting for RawrZ Security Platform... (attempt %attempt%/%max_attempts%)"
timeout /t 10 /nobreak >nul
set /a attempt+=1
goto wait_loop

REM Run health checks
:run_health_checks
call :log_info "Running health checks..."

curl -f http://localhost:8080/api/status >nul 2>&1
if not errorlevel 1 (
    call :log_success "Main application health check passed"
) else (
    call :log_error "Main application health check failed"
    exit /b 1
)

docker-compose -f %DOCKER_COMPOSE_FILE% exec -T postgres pg_isready -U rawrz >nul 2>&1
if not errorlevel 1 (
    call :log_success "Database health check passed"
) else (
    call :log_error "Database health check failed"
    exit /b 1
)

docker-compose -f %DOCKER_COMPOSE_FILE% exec -T redis redis-cli ping >nul 2>&1
if not errorlevel 1 (
    call :log_success "Redis health check passed"
) else (
    call :log_error "Redis health check failed"
    exit /b 1
)
goto :eof

REM Show deployment information
:show_deployment_info
call :log_success "Deployment completed successfully!"
echo.
echo RawrZ Security Platform is now running:
echo   - Web Interface: https://localhost
echo   - API Endpoint: https://localhost/api/status
echo   - Health Check: https://localhost/health
echo.
echo To view logs:
echo   docker-compose -f %DOCKER_COMPOSE_FILE% logs -f
echo.
echo To stop services:
echo   docker-compose -f %DOCKER_COMPOSE_FILE% down
echo.
echo To restart services:
echo   docker-compose -f %DOCKER_COMPOSE_FILE% restart
goto :eof

REM Main deployment function
:main
call :log_info "Starting RawrZ Security Platform deployment..."

call :check_docker
if errorlevel 1 exit /b 1

call :check_env_file
if errorlevel 1 exit /b 1

call :create_directories
call :generate_ssl_certificates
call :deploy_services
call :wait_for_services
call :run_health_checks
call :show_deployment_info
goto :eof

REM Handle script arguments
if "%1"=="deploy" goto main
if "%1"=="stop" goto stop_services
if "%1"=="restart" goto restart_services
if "%1"=="logs" goto show_logs
if "%1"=="status" goto show_status
if "%1"=="clean" goto clean_services
if "%1"=="" goto main

echo Usage: %0 {deploy^|stop^|restart^|logs^|status^|clean}
echo.
echo Commands:
echo   deploy  - Deploy the RawrZ Security Platform (default)
echo   stop    - Stop all services
echo   restart - Restart all services
echo   logs    - View service logs
echo   status  - Show service status
echo   clean   - Stop services and clean up volumes
exit /b 1

:stop_services
call :log_info "Stopping RawrZ Security Platform..."
docker-compose -f %DOCKER_COMPOSE_FILE% down
call :log_success "Services stopped"
goto :eof

:restart_services
call :log_info "Restarting RawrZ Security Platform..."
docker-compose -f %DOCKER_COMPOSE_FILE% restart
call :log_success "Services restarted"
goto :eof

:show_logs
docker-compose -f %DOCKER_COMPOSE_FILE% logs -f
goto :eof

:show_status
docker-compose -f %DOCKER_COMPOSE_FILE% ps
goto :eof

:clean_services
call :log_info "Cleaning up RawrZ Security Platform..."
docker-compose -f %DOCKER_COMPOSE_FILE% down -v --remove-orphans
docker system prune -f
call :log_success "Cleanup completed"
goto :eof
