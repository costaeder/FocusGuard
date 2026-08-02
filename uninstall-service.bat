@echo off
:: Script para desinstalar o servico FocusGuard
:: Execute como Administrador

echo ==========================================
echo   FocusGuard - Desinstalacao do Servico
echo ==========================================
echo.

:: Verifica se está rodando como admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERRO: Execute este script como Administrador!
    pause
    exit /b 1
)

set SERVICE_NAME=FocusGuard Service

:: Para o serviço
echo Parando servico...
sc stop "%SERVICE_NAME%" >nul 2>&1
timeout /t 3 /nobreak >nul

:: Remove o serviço
echo Removendo servico...
sc delete "%SERVICE_NAME%"

if %errorLevel% neq 0 (
    echo AVISO: Servico pode nao existir ou ja foi removido.
) else (
    echo Servico removido com sucesso!
)

echo.
echo ==========================================
echo   Desinstalacao concluida!
echo ==========================================
echo.
pause
