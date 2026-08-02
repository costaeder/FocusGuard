# FocusGuard - Script de Publicacao
# Executa como Administrador

param(
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$ServiceName = "FocusGuard Service"
$InstallPath = "C:\Program Files\FocusGuard"
$ProjectPath = $PSScriptRoot

Write-Host "=== FocusGuard Publish ===" -ForegroundColor Cyan
Write-Host ""

# 1. Para o servico
Write-Host "[1/6] Parando servico..." -ForegroundColor Yellow
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    Write-Host "      Servico parado" -ForegroundColor Green
} else {
    Write-Host "      Servico nao instalado (sera criado)" -ForegroundColor Gray
}

# 2. Mata processos relacionados
Write-Host "[2/6] Matando processos..." -ForegroundColor Yellow
$processes = @("FocusGuard.Service", "FocusGuard.Manager")
foreach ($proc in $processes) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1
Write-Host "      Processos finalizados" -ForegroundColor Green

# 3. Compila em Release
if (-not $SkipBuild) {
    Write-Host "[3/6] Compilando em Release..." -ForegroundColor Yellow
    Push-Location $ProjectPath
    dotnet publish FocusGuard.Service -c Release -r win-x64 --self-contained true -o "$ProjectPath\publish\service"
    dotnet publish FocusGuard.Manager -c Release -r win-x64 --self-contained true -o "$ProjectPath\publish\manager"
    Pop-Location
    Write-Host "      Compilacao concluida" -ForegroundColor Green
} else {
    Write-Host "[3/6] Build ignorado (SkipBuild)" -ForegroundColor Gray
}

# 4. Cria pasta de instalacao
Write-Host "[4/6] Copiando arquivos..." -ForegroundColor Yellow
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

# Copia servico
$serviceDest = "$InstallPath\Service"
if (Test-Path $serviceDest) { Remove-Item -Path $serviceDest -Recurse -Force }
Copy-Item -Path "$ProjectPath\publish\service" -Destination $serviceDest -Recurse -Force

# Copia manager
$managerDest = "$InstallPath\Manager"
if (Test-Path $managerDest) { Remove-Item -Path $managerDest -Recurse -Force }
Copy-Item -Path "$ProjectPath\publish\manager" -Destination $managerDest -Recurse -Force

Write-Host "      Arquivos copiados para $InstallPath" -ForegroundColor Green

# 5. Reinstala servico
Write-Host "[5/6] Configurando servico..." -ForegroundColor Yellow
$servicePath = "$InstallPath\Service\FocusGuard.Service.exe"

# Remove servico antigo se existir
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Cria novo servico
sc.exe create $ServiceName binPath= $servicePath start= auto DisplayName= $ServiceName | Out-Null
sc.exe description $ServiceName "Servico de protecao de foco e produtividade" | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

Write-Host "      Servico configurado" -ForegroundColor Green

# 6. Inicia servico
Write-Host "[6/6] Iniciando servico..." -ForegroundColor Yellow
Start-Service -Name $ServiceName
Start-Sleep -Seconds 2

$service = Get-Service -Name $ServiceName
if ($service.Status -eq "Running") {
    Write-Host "      Servico iniciado com sucesso!" -ForegroundColor Green
} else {
    Write-Host "      AVISO: Servico nao iniciou automaticamente" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Publicacao Concluida ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Locais instalados:" -ForegroundColor White
Write-Host "  Servico: $InstallPath\Service\FocusGuard.Service.exe" -ForegroundColor Gray
Write-Host "  Manager: $InstallPath\Manager\FocusGuard.Manager.exe" -ForegroundColor Gray
Write-Host ""

# 7. Abre o Manager
Write-Host "[7/7] Abrindo Manager..." -ForegroundColor Yellow
Start-Process -FilePath "$InstallPath\Manager\FocusGuard.Manager.exe" -Verb RunAs
Write-Host "      Manager aberto" -ForegroundColor Green
Write-Host ""
