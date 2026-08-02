@echo off
REM ============================================================
REM  FocusGuard - Reativacao do servico (rodar como ADMIN)
REM  - Reaponta o binario para C:\ (estava apontando para E:\)
REM  - Reabilita inicio automatico (estava DISABLED)
REM  - Limpa o log antigo de ~279 MB
REM  - Inicia o servico
REM ============================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERRO] Este script precisa ser executado como ADMINISTRADOR.
    echo Clique com o botao direito no arquivo e escolha "Executar como administrador".
    echo.
    pause
    exit /b 1
)

set "SVC=FocusGuard Service"
set "EXE=C:\Dev\FocusGuard\publish\service\FocusGuard.Service.exe"

if not exist "%EXE%" (
    echo [ERRO] Executavel nao encontrado: %EXE%
    pause
    exit /b 1
)

echo.
echo [1/5] Parando servico (se estiver rodando)...
sc stop "%SVC%" >nul 2>&1

echo [2/5] Reapontando binario para: %EXE%
sc config "%SVC%" binPath= "%EXE%" start= auto
if %errorlevel% neq 0 (
    echo [ERRO] Falha ao reconfigurar o servico.
    pause
    exit /b 1
)

echo [3/5] Limpando log antigo...
del /f /q "%ProgramData%\FocusGuard\service.log" >nul 2>&1

echo [4/5] Iniciando servico...
sc start "%SVC%"

echo [5/5] Status atual:
sc query "%SVC%"

echo.
echo ============================================================
echo  Pronto. Se o ESTADO acima estiver "RUNNING", o FocusGuard
echo  esta ativo e bloqueando. O log fica em:
echo  %ProgramData%\FocusGuard\service.log
echo ============================================================
echo.
pause
