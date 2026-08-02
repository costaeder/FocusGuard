# Adiciona lista curada de proxies web a blocklist do config.json
$cfgPath = Join-Path $env:ProgramData "FocusGuard\config.json"
$cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
$proxies = @(
 "croxyproxy.com","croxy.network","croxyproxy.rocks","croxyproxy.net","proxysite.com",
 "proxyium.com","blockaway.net","hide.me","hidester.com","hidemyass.com",
 "kproxy.com","4everproxy.com","genmirror.com","filterbypass.me","proxfree.com",
 "vpnbook.com","zalmos.com","boomproxy.com","freeproxy.win","megaproxy.com",
 "anonymouse.org","dontfilter.us","newipnow.com","hidemy.name","plainproxies.com",
 "my-proxy.com","unblockweb.co","proxyscrape.com","spys.one","freeproxylists.net"
)
$set = [System.Collections.Generic.HashSet[string]]::new([string[]]$cfg.BlockedSites,[System.StringComparer]::OrdinalIgnoreCase)
$added = 0
foreach ($p in $proxies) { if ($set.Add($p)) { $added++ } }
$cfg.BlockedSites = @($set)
$cfg.LastUpdated = (Get-Date).ToUniversalTime().ToString("o")
($cfg | ConvertTo-Json -Depth 10) | Set-Content $cfgPath -Encoding UTF8
Write-Host "Proxies novos adicionados: $added | total blocklist: $($cfg.BlockedSites.Count)"
