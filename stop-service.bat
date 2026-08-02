@echo off
net session >nul 2>&1
if %errorlevel% neq 0 ( echo Rode como ADMINISTRADOR & pause & exit /b 1 )

set "SVC=FocusGuard Service"

echo Desligando recuperacao automatica (anti-tamper) temporariamente...
sc failureflag "%SVC%" 0 >nul 2>&1
sc failure "%SVC%" reset=0 actions="" >nul 2>&1

echo Parando servico...
sc stop "%SVC%" >nul 2>&1

:waitloop
sc query "%SVC%" | find "STOPPED" >nul
if errorlevel 1 (
    timeout /t 2 /nobreak >nul
    goto waitloop
)
echo Servico PARADO. Pode fechar esta janela.
timeout /t 3 /nobreak >nul
