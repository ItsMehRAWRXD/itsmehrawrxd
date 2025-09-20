@echo off
echo RawrZ Security Platform - Deployment Script
echo ===========================================
echo.

echo Installing Node.js dependencies...
call npm install

echo.
echo Starting RawrZ Security Platform...
echo Access the platform at: http://localhost:3000
echo.

node api-server-real.js
