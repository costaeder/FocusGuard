@echo off
sc stop "FocusGuard Service"
timeout /t 3 /nobreak >nul
sc delete "FocusGuard Service"
exit /b 0
