@echo off
REM Android Development Startup Script for Windows

echo Starting Android Development Environment...

REM Check for Docker
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Docker Desktop not found
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

echo Using container engine: Docker

REM Start Android development container
echo Starting Android development container...
docker run -it --rm ^
    -v "%cd%":/workspace ^
    -p 8080:8080 ^
    -p 8081:8081 ^
    -p 8082:8082 ^
    -p 8083:8083 ^
    -p 8084:8084 ^
    -p 5555:5555 ^
    -p 5556:5556 ^
    --name android-dev-container ^
    mobile-android-dev

echo Android Development Environment started!
echo Access IDE at: http://localhost:8080
pause
