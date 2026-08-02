@echo off
set INSTALL_DIR=%~dp0
sc create "FocusGuard Service" binPath="%INSTALL_DIR%FocusGuard.Service.exe" start=auto DisplayName="FocusGuard Service"
sc description "FocusGuard Service" "Servico de protecao de foco e produtividade"
sc start "FocusGuard Service"
exit /b 0
