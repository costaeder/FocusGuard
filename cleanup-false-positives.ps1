# Limpa falsos positivos do config.json e analysis_cache.json

$configPath = "$env:ProgramData\FocusGuard\config.json"
$cachePath = "$env:ProgramData\FocusGuard\analysis_cache.json"

# Dominios legitimos que foram bloqueados por engano
$falsePositives = @(
    "stripe.com", "stripe.click", "stripe.uno", "stripe.pt", "stripe.gg",
    "stripe.cx", "stripe.es", "stripe.app", "stripe.club", "stripe.to", "stripe.space",
    "nvidia.com", "geforce.com", "logitechg.com", "nvidiagrid.net",
    "matomo.org", "matomo.click", "matomo.xyz", "matomo.pk", "matomo.jp", "matomo.cloud",
    "cookielaw.org", "onetrust.com", "pendo.io",
    "backblazeb2.com", "backblaze.com",
    "de.com",
    "42locacoes.com.br"
)

# 1. Limpa config.json
Write-Host "=== Limpando config.json ===" -ForegroundColor Cyan
$config = Get-Content $configPath | ConvertFrom-Json
$before = $config.BlockedSites.Count

$config.BlockedSites = @($config.BlockedSites | Where-Object { $_ -notin $falsePositives })
$config.LastUpdated = (Get-Date).ToUniversalTime().ToString("o")

$after = $config.BlockedSites.Count
Write-Host "  Removidos: $($before - $after) falsos positivos" -ForegroundColor Green
Write-Host "  Restam: $after sites bloqueados" -ForegroundColor Gray

$config | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding UTF8
Write-Host "  config.json salvo" -ForegroundColor Green

# 2. Limpa analysis_cache.json (remove entradas de falsos positivos)
Write-Host ""
Write-Host "=== Limpando analysis_cache.json ===" -ForegroundColor Cyan
if (Test-Path $cachePath) {
    $cache = Get-Content $cachePath | ConvertFrom-Json
    $cacheBefore = $cache.Count

    $cache = @($cache | Where-Object { $_.Domain -notin $falsePositives })

    $cacheAfter = $cache.Count
    Write-Host "  Removidos: $($cacheBefore - $cacheAfter) entradas do cache" -ForegroundColor Green

    $cache | ConvertTo-Json -Depth 10 | Set-Content $cachePath -Encoding UTF8
    Write-Host "  analysis_cache.json salvo" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== Limpeza concluida ===" -ForegroundColor Cyan
