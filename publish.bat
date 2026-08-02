@echo off
:: Script para compilar e publicar o FocusGuard

echo ========================================
echo   FocusGuard - Build e Publish
echo ========================================
echo.

cd /d "%~dp0"

echo Restaurando pacotes...
dotnet restore

echo.
echo Compilando solucao...
dotnet build -c Release

if %errorLevel% neq 0 (
    echo ERRO: Falha na compilacao!
    pause
    exit /b 1
)

echo.
echo Publicando Servico...
dotnet publish FocusGuard.Service -c Release -o publish

echo.
echo Publicando Manager...
dotnet publish FocusGuard.Manager -c Release -o publish

echo.
echo ========================================
echo   Build concluido!
echo ========================================
echo.
echo Arquivos em: %~dp0publish
echo.
echo Proximos passos:
echo   1. Execute install-service.bat como Admin
echo   2. Execute publish\FocusGuard.Manager.exe
echo.
pause
