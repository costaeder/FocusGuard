@echo off
:: Script para compilar e gerar o instalador do FocusGuard
:: Requer: Inno Setup 6.x instalado

echo ========================================
echo   FocusGuard - Build Installer
echo ========================================
echo.

cd /d "%~dp0"

:: Verifica se Inno Setup esta instalado
set ISCC=
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" (
    set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
) else if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" (
    set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
)

if "%ISCC%"=="" (
    echo ERRO: Inno Setup 6 nao encontrado!
    echo.
    echo Baixe em: https://jrsoftware.org/isdl.php
    echo.
    pause
    exit /b 1
)

echo [1/3] Restaurando pacotes...
dotnet restore
if %errorLevel% neq 0 (
    echo ERRO: Falha ao restaurar pacotes!
    pause
    exit /b 1
)

echo.
echo [2/3] Publicando aplicacao...
dotnet publish FocusGuard.Service -c Release -o publish
dotnet publish FocusGuard.Manager -c Release -o publish
if %errorLevel% neq 0 (
    echo ERRO: Falha na publicacao!
    pause
    exit /b 1
)

echo.
echo [3/3] Gerando instalador...
"%ISCC%" installer.iss
if %errorLevel% neq 0 (
    echo ERRO: Falha ao gerar instalador!
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Instalador criado com sucesso!
echo ========================================
echo.
echo Arquivo: installer-output\FocusGuard-Setup.exe
echo.
pause
