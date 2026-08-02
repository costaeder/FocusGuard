@echo off
net session >nul 2>&1
if %errorlevel% neq 0 ( echo Rode como ADMINISTRADOR & pause & exit /b 1 )

set "SVC=FocusGuard Service"

echo Garantindo inicio automatico...
sc config "%SVC%" start= auto >nul 2>&1

echo Limpando log...
del /f /q "%ProgramData%\FocusGuard\service.log" >nul 2>&1

echo Iniciando servico...
sc start "%SVC%"

echo.
echo Status:
sc query "%SVC%"
echo.
pause
