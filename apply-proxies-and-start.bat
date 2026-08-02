@echo off
net session >nul 2>&1
if %errorlevel% neq 0 ( echo Rode como ADMINISTRADOR & pause & exit /b 1 )

set "SVC=FocusGuard Service"

echo Adicionando lista de proxies ao config...
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Dev\FocusGuard\add-proxies.ps1"

echo Limpando log...
del /f /q "%ProgramData%\FocusGuard\service.log" >nul 2>&1

echo Garantindo inicio automatico e iniciando servico...
sc config "%SVC%" start= auto >nul 2>&1
sc start "%SVC%"

echo.
echo Status:
sc query "%SVC%"
echo.
pause
