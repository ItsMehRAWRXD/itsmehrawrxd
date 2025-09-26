@echo off
echo  Starting RawrZ Security Platform Panel...
echo.
echo  Main Panel: http://localhost:3000
echo  API Endpoint: http://localhost:3000/api/rawrz-engine/status
echo.
echo Press Ctrl+C to stop the server
echo.
node api-server.js
pause
