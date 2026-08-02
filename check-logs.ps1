$logs = Get-WinEvent -LogName Application -MaxEvents 500 | Where-Object {
    $_.ProviderName -eq ".NET Runtime" -and $_.Message -match "FocusGuard"
} | Select-Object -First 10

foreach ($log in $logs) {
    Write-Host "=== $($log.TimeCreated) ===" -ForegroundColor Cyan
    Write-Host $log.Message
    Write-Host ""
}

if (-not $logs) {
    Write-Host "Nenhum log .NET Runtime encontrado. Verificando logs gerais..." -ForegroundColor Yellow

    # Tenta via journalctl-style (Windows Event)
    Get-WinEvent -LogName Application -MaxEvents 100 | Where-Object {
        $_.Message -match "FocusGuard|backblaze|whitelist"
    } | Select-Object -First 10 | ForEach-Object {
        Write-Host "=== $($_.TimeCreated) | $($_.ProviderName) ===" -ForegroundColor Cyan
        Write-Host $_.Message.Substring(0, [Math]::Min(500, $_.Message.Length))
        Write-Host ""
    }
}
