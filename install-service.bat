@echo off
echo Instalando FocusGuard Service...
sc create "FocusGuard Service" binPath="D:\Dev\Personal\FocusGuard\FocusGuard.Service\bin\Release\net9.0-windows\win-x64\FocusGuard.Service.exe" start=auto DisplayName="FocusGuard Service"
sc description "FocusGuard Service" "Servico de protecao de foco e produtividade"
echo.
echo Iniciando servico...
sc start "FocusGuard Service"
echo.
echo Concluido!
pause
