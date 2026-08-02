@echo off
REM ============================================================
REM  FocusGuard - Atualiza o binario do servico (rodar como ADMIN)
REM  Desliga o anti-tamper temporariamente, para o servico,
REM  republica o codigo novo e reinicia. A protecao volta
REM  sozinha quando o servico inicia.
REM ============================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERRO] Rode este script como ADMINISTRADOR.
    echo Clique com o botao direito e escolha "Executar como administrador".
    echo.
    pause
    exit /b 1
)

set "SVC=FocusGuard Service"
set "DOTNET=C:\Program Files\dotnet\dotnet.exe"

echo [1/6] Desligando recuperacao automatica (anti-tamper)...
sc failureflag "%SVC%" 0 >nul 2>&1
sc failure "%SVC%" reset=0 actions="" >nul 2>&1

echo [2/6] Parando servico...
sc stop "%SVC%" >nul 2>&1

echo Aguardando servico parar...
:waitloop
sc query "%SVC%" | find "STOPPED" >nul
if errorlevel 1 (
    timeout /t 2 /nobreak >nul
    goto waitloop
)
echo Servico parado.

echo [3/6] Republicando servico (correcao da IA)...
cd /d C:\Dev\FocusGuard
"%DOTNET%" publish FocusGuard.Service\FocusGuard.Service.csproj -c Release -o publish\service --nologo
if %errorlevel% neq 0 (
    echo [ERRO] Falha ao publicar. Iniciando o servico com a versao anterior...
    sc start "%SVC%"
    pause
    exit /b 1
)

echo [4/6] Limpando log...
del /f /q "%ProgramData%\FocusGuard\service.log" >nul 2>&1

echo [5/6] Iniciando servico...
sc start "%SVC%"

echo [6/6] Status:
sc query "%SVC%"

echo.
echo ============================================================
echo  Pronto. O servico reativa o anti-tamper sozinho ao iniciar.
echo  Acompanhe a IA no log:
echo  %ProgramData%\FocusGuard\service.log
echo ============================================================
echo.
pause
