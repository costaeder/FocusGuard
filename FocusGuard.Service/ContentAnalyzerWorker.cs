using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using FocusGuard.Shared.Models;
using FocusGuard.Shared.Services;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace FocusGuard.Service;

/// <summary>
/// Worker que monitora DNS queries e analisa sites novos em busca de conteudo adulto/distracao
/// </summary>
public partial class ContentAnalyzerWorker : BackgroundService
{
    private readonly ILogger<ContentAnalyzerWorker> _logger;
    private readonly BlockedDomainStore _blockedStore;
    private readonly DnsQueryNotifier _queryNotifier;
    private readonly TimeSpan _checkInterval = TimeSpan.FromSeconds(30);
    private readonly AnalysisCache _cache = new();
    private readonly HashSet<string> _pendingAnalysis = [];
    private readonly object _lock = new();
    private DateTime _lastDnsCacheCheck = DateTime.MinValue;

    // === Bloqueio progressivo por confianca/score ===
    // A cada deteccao de categoria ruim, soma-se pontos ao score acumulado do dominio.
    // Ao atingir config.ContentAnalysisThreshold, o dominio e bloqueado de fato.
    // Enquanto abaixo do limite, apenas um AVISO e registrado (bloqueia ao reincidir).
    private const int ScoreAiAdult = 10;
    private const int ScoreAiGambling = 10;
    private const int ScoreAiDistraction = 6;
    private const int ScoreAiProxy = 100;      // proxies existem pra burlar o filtro -> bloqueia imediato
    private const int ScoreDnsConfirmed = 100; // DNS family confirmou -> quase certo, bloqueia imediato
    private const int ScoreNameMatch = 100;    // nome corresponde a dominio ja bloqueado -> imediato

    // Dominios que nunca devem ser analisados/bloqueados
    private static readonly HashSet<string> Whitelist =
    [
        // Microsoft
        "microsoft.com", "windows.com", "office.com", "live.com", "outlook.com",
        "bing.com", "msn.com", "azure.com", "visualstudio.com", "github.com",
        "windowsupdate.com", "update.microsoft.com",

        // Google
        "google.com", "googleapis.com", "gstatic.com", "google.com.br",
        "youtube.com", "googlevideo.com", "ytimg.com",
        "gmail.com", "googleusercontent.com",

        // Cloudflare/DNS
        "cloudflare.com", "cloudflare-dns.com", "one.one.one.one",
        "opendns.com", "cleanbrowsing.org",

        // Desenvolvimento
        "stackoverflow.com", "npmjs.com", "nuget.org", "pypi.org",
        "docker.com", "gitlab.com", "bitbucket.org",

        // Redes sociais (nao bloquear automaticamente)
        "linkedin.com", "twitter.com", "x.com",

        // Bancos/Financeiro
        "bancodobrasil.com.br", "itau.com.br", "bradesco.com.br",
        "santander.com.br", "caixa.gov.br", "nubank.com.br",

        // Governo
        "gov.br", "receita.fazenda.gov.br",

        // E-commerce legitimo
        "amazon.com", "amazon.com.br", "mercadolivre.com.br",
        "magazineluiza.com.br", "americanas.com.br",

        // CDNs
        "akamaized.net", "cloudfront.net", "fastly.net", "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com", "unpkg.com", "rawcdn.githack.com",

        // Cloud Storage / Object Storage (dominios genericos que hospedam qualquer conteudo)
        "backblazeb2.com", "backblaze.com",                        // Backblaze B2
        "s3.amazonaws.com", "s3.us-east-1.amazonaws.com",          // AWS S3
        "amazonaws.com",                                            // AWS geral
        "blob.core.windows.net", "azureedge.net",                  // Azure
        "storage.googleapis.com",                                   // Google Cloud Storage
        "digitaloceanspaces.com",                                   // DigitalOcean Spaces
        "r2.cloudflarestorage.com",                                 // Cloudflare R2
        "supabase.co", "supabase.com",                              // Supabase
        "firebasestorage.googleapis.com",                           // Firebase Storage
        "objects-us-east-1.dream.io",                               // DreamObjects
        "wasabisys.com",                                            // Wasabi
        "imgur.com", "i.imgur.com",                                 // Imgur

        // Portais/Busca
        "yahoo.com", "yahoo.com.br",

        // Sites do usuario
        "escaladaonline.com.br", "hookwave.com.br",

        // Sistema
        "localhost", "local", "home", "router", "gateway"
    ];

    // Extensoes de dominio que indicam sites de sistema/CDN
    private static readonly string[] IgnoredTlds =
    [
        ".local", ".lan", ".home", ".internal",
        ".arpa", ".test", ".invalid", ".localhost"
    ];

    public ContentAnalyzerWorker(
        ILogger<ContentAnalyzerWorker> logger,
        BlockedDomainStore blockedStore,
        DnsQueryNotifier queryNotifier)
    {
        _logger = logger;
        _blockedStore = blockedStore;
        _queryNotifier = queryNotifier;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var config = AppConfig.Load();
        _logger.LogInformation("Content Analyzer iniciado (DryRun: {DryRun}, Enabled: {Enabled})",
            config.DryRun, config.ContentAnalysisEnabled);

        _cache.Load();

        // Sincroniza sites que foram detectados em DryRun mas não foram bloqueados
        if (!config.DryRun)
        {
            await SyncCachedBlockedSitesAsync(config);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                _logger.LogInformation("[CICLO] Inicio do ciclo");
                config = AppConfig.Load();

                if (config.ContentAnalysisEnabled)
                {
                    // 1. Coleta dominios do DNS proxy (ou fallback ipconfig)
                    var domains = _queryNotifier.DrainAll();
                    if (domains.Count == 0)
                        domains = await GetDomainsFromDnsCacheAsync(); // fallback se proxy nao esta ativo
                    _logger.LogInformation("[CICLO] Dominios: {Count} ({Source})",
                        domains.Count, domains.Count > 0 ? "proxy" : "vazio");

                    // 2. Separa reincidencias (ja em cache como ruins, ainda nao bloqueadas)
                    //    de dominios novos. Reincidencia acumula confianca SEM nova chamada de IA.
                    var toAnalyze = new List<string>();
                    foreach (var domain in domains)
                    {
                        if (IsWhitelisted(domain)) continue;
                        if (IgnoredTlds.Any(tld => domain.EndsWith(tld, StringComparison.OrdinalIgnoreCase))) continue;
                        if (_blockedStore.IsBlocked(domain)) continue; // ja bloqueado

                        var cached = _cache.Get(domain);
                        if (cached != null)
                        {
                            if (!cached.IsBlocked && !cached.AnalysisFailed && IsBadCategory(cached.Category))
                            {
                                // Reincidencia: usuario voltou a acessar site ja sinalizado -> sobe a confianca.
                                _logger.LogInformation("[REINCIDENCIA] {Domain} (cat={Category}, score atual={Score})",
                                    domain, cached.Category, cached.Score);
                                await ProcessBadDetectionAsync(cached, config, AiScoreIncrement(cached.Category), "reincidencia");
                            }
                            continue; // safe, bloqueado ou ja tratado nesta rodada
                        }

                        lock (_lock)
                        {
                            if (_pendingAnalysis.Contains(domain)) continue;
                            _pendingAnalysis.Add(domain);
                        }
                        toAnalyze.Add(domain);
                    }

                    if (toAnalyze.Count > 0)
                        _logger.LogInformation("[CICLO] Novos para analise: {Count} -> {Domains}",
                            toAnalyze.Count, string.Join(", ", toAnalyze.Take(15)));

                    // 3. Analisa novos (max 10/ciclo): DNS/nome, depois IA
                    var pendingAiBatch = new List<string>();

                    foreach (var domain in toAnalyze.Take(10))
                    {
                        _logger.LogInformation("[ANALISE] Etapa 1-2 (DNS/nome): {Domain}", domain);
                        var handled = await AnalyzeByDnsAndNameAsync(domain, config);
                        if (handled)
                        {
                            _logger.LogInformation("[ANALISE] {Domain} -> tratado por DNS/nome", domain);
                        }
                        else if (config.UseAiAnalysis && !string.IsNullOrEmpty(config.AiApiKey))
                        {
                            _logger.LogInformation("[ANALISE] {Domain} -> enfileirado para IA", domain);
                            pendingAiBatch.Add(domain);
                        }
                        else
                        {
                            // Sem IA, marca como safe
                            _cache.Set(new AnalyzedSite { Domain = domain, Score = 0, Category = "safe" });
                            MarkDomainDone(domain);
                        }
                    }

                    // Libera dominios excedentes (> 10) para reanalise no proximo ciclo
                    foreach (var domain in toAnalyze.Skip(10))
                    {
                        lock (_lock) _pendingAnalysis.Remove(domain);
                    }

                    // 4. Envia batch para IA (se habilitado e houver dominios pendentes)
                    if (pendingAiBatch.Count > 0)
                    {
                        _logger.LogInformation("[IA] Enviando batch de {Count} dominios: {Domains}",
                            pendingAiBatch.Count, string.Join(", ", pendingAiBatch));
                        await AnalyzeByAiBatchAsync(pendingAiBatch, config);
                    }

                    // 5. Salva cache periodicamente
                    _cache.Save();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no Content Analyzer");
            }

            await Task.Delay(_checkInterval, stoppingToken);
        }
    }

    /// <summary>
    /// Obtem dominios do cache DNS do Windows usando ipconfig /displaydns
    /// </summary>
    private async Task<HashSet<string>> GetDomainsFromDnsCacheAsync()
    {
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "ipconfig",
                    Arguments = "/displaydns",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true,
                    StandardOutputEncoding = System.Text.Encoding.UTF8
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();

            // Extrai dominios do output
            // Formato: "    Record Name . . . . . : exemplo.com"
            var matches = DnsCacheRegex().Matches(output);
            foreach (Match match in matches)
            {
                var domain = match.Groups[1].Value.Trim().ToLowerInvariant();

                // Remove subdominios para obter dominio principal
                domain = GetBaseDomain(domain);

                if (!string.IsNullOrEmpty(domain) && domain.Contains('.'))
                {
                    domains.Add(domain);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erro ao ler cache DNS");
        }

        return domains;
    }

    /// <summary>
    /// Extrai o dominio base (ex: sub.example.com -> example.com)
    /// </summary>
    private static string GetBaseDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain))
            return domain;

        // Remove trailing dot se houver
        domain = domain.TrimEnd('.');

        var parts = domain.Split('.');
        if (parts.Length <= 2)
            return domain;

        // Trata dominios .com.br, .co.uk, etc.
        if (parts.Length >= 3 &&
            (parts[^2] == "com" || parts[^2] == "co" || parts[^2] == "org" || parts[^2] == "gov" || parts[^2] == "edu"))
        {
            return string.Join(".", parts[^3..]);
        }

        return string.Join(".", parts[^2..]);
    }

    /// <summary>
    /// Verifica se dominio esta na whitelist.
    /// Usado tambem pelo DnsProxyWorker para evitar bloqueio de dominios legitimos.
    /// </summary>
    internal static bool IsWhitelisted(string domain)
    {
        foreach (var white in Whitelist)
        {
            if (domain.Equals(white, StringComparison.OrdinalIgnoreCase) ||
                domain.EndsWith("." + white, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        // Verifica excecoes do usuario no config
        try
        {
            var config = AppConfig.Load();
            foreach (var white in config.WhitelistedSites)
            {
                if (domain.Equals(white, StringComparison.OrdinalIgnoreCase) ||
                    domain.EndsWith("." + white, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
        }
        catch { }

        return false;
    }

    /// <summary>
    /// Etapas 1-2: DNS family check + nome ja bloqueado. Retorna true se tratou o dominio.
    /// </summary>
    private async Task<bool> AnalyzeByDnsAndNameAsync(string domain, AppConfig config)
    {
        try
        {
            // === ETAPA 1: Verifica se o dominio é bloqueado pelos DNS family providers ===
            var (isBlockedByDns, blockedBy) = await DnsService.IsDomainBlockedByFamilyDnsAsync(
                domain, msg => _logger.LogDebug(msg));

            if (isBlockedByDns)
            {
                // Confirmado pelo DNS family -> confianca alta, bloqueia imediatamente
                var site = new AnalyzedSite
                {
                    Domain = domain,
                    Category = "adult",
                    MatchedKeywords = [$"dns-blocked:{blockedBy}"]
                };
                await ProcessBadDetectionAsync(site, config, ScoreDnsConfirmed, $"dns:{blockedBy}");
                return true;
            }

            // === ETAPA 2: Verifica se o nome do dominio já corresponde a um dominio bloqueado ===
            if (IsDomainNameAlreadyBlocked(domain, config))
            {
                // Nome corresponde a dominio ja bloqueado -> confianca alta, bloqueia imediatamente
                var site = new AnalyzedSite
                {
                    Domain = domain,
                    Category = "adult",
                    MatchedKeywords = ["nome-bloqueado"]
                };
                await ProcessBadDetectionAsync(site, config, ScoreNameMatch, "nome-bloqueado");
                return true;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Erro na analise DNS/nome de {Domain}", domain);
        }

        return false;
    }

    /// <summary>
    /// Analise por IA em batch: envia todos os dominios pendentes de uma vez para a OpenAI
    /// </summary>
    private async Task AnalyzeByAiBatchAsync(List<string> domains, AppConfig config)
    {
        try
        {
            var classifications = await AiContentAnalyzerService.AnalyzeBatchAsync(
                domains,
                config.AiApiKey,
                config.AiModel,
                msg => _logger.LogInformation(msg));

            _logger.LogInformation("[IA] Resposta: {Count} classificacoes recebidas", classifications.Count);

            // Mapeia resultados por dominio
            var resultMap = classifications.ToDictionary(
                c => c.Domain.ToLowerInvariant(),
                c => c,
                StringComparer.OrdinalIgnoreCase);

            foreach (var domain in domains)
            {
                if (resultMap.TryGetValue(domain.ToLowerInvariant(), out var classification))
                {
                    var category = (classification.Category ?? "safe").ToLowerInvariant();
                    if (IsBadCategory(category))
                    {
                        // Primeira deteccao pela IA: inicia a acumulacao de confianca
                        // (avisa agora; bloqueia quando o score acumulado atingir o limite).
                        var site = new AnalyzedSite
                        {
                            Domain = domain.ToLowerInvariant(),
                            Category = category,
                            MatchedKeywords = ["ai:" + category]
                        };
                        await ProcessBadDetectionAsync(site, config, AiScoreIncrement(category), "ia");
                    }
                    else
                    {
                        _logger.LogInformation("[IA] {Domain} -> safe", domain);
                        _cache.Set(new AnalyzedSite
                        {
                            Domain = domain.ToLowerInvariant(),
                            Score = 0,
                            Category = "safe",
                            MatchedKeywords = ["ai:safe"]
                        });
                        MarkDomainDone(domain);
                    }
                }
                else
                {
                    _logger.LogWarning("[IA] Dominio nao retornado pela IA: {Domain}", domain);
                    // IA nao retornou este dominio - marca como safe
                    _cache.Set(new AnalyzedSite
                    {
                        Domain = domain,
                        Score = 0,
                        Category = "safe",
                        MatchedKeywords = ["ai:no-response"]
                    });
                    MarkDomainDone(domain);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro na analise IA em batch");
            foreach (var domain in domains)
                MarkDomainDone(domain);
        }
    }

    private void MarkDomainDone(string domain)
    {
        lock (_lock)
        {
            _pendingAnalysis.Remove(domain);
        }
    }

    /// <summary>Categorias consideradas para bloqueio progressivo.</summary>
    private static bool IsBadCategory(string category) =>
        category is "adult" or "gambling" or "distraction" or "proxy";

    /// <summary>Pontos de confianca somados por deteccao da IA, conforme a severidade da categoria.</summary>
    private static int AiScoreIncrement(string category) => category switch
    {
        "adult" => ScoreAiAdult,
        "gambling" => ScoreAiGambling,
        "distraction" => ScoreAiDistraction,
        "proxy" => ScoreAiProxy,
        _ => 0
    };

    /// <summary>
    /// Nucleo do bloqueio progressivo: soma pontos de confianca ao dominio e decide entre
    /// AVISAR (score ainda abaixo do limite) ou BLOQUEAR (score >= ContentAnalysisThreshold).
    /// Atualiza o cache e libera o dominio da fila de pendentes.
    /// </summary>
    private async Task ProcessBadDetectionAsync(AnalyzedSite site, AppConfig config, int increment, string source)
    {
        var existing = _cache.Get(site.Domain);
        if (existing != null && !ReferenceEquals(existing, site))
        {
            // Usa o registro ja existente no cache para nao perder o score acumulado
            existing.Category = site.Category;
            existing.MatchedKeywords = site.MatchedKeywords;
            site = existing;
        }

        site.Score += increment;
        site.Hits += 1;
        site.AnalyzedAt = DateTime.UtcNow;

        var threshold = config.ContentAnalysisThreshold;

        if (site.Score >= threshold)
        {
            if (config.DryRun)
            {
                _logger.LogWarning("[IA] [DRY-RUN] Bloquearia {Domain} (cat={Category}, score={Score}>={Threshold}, hits={Hits}, {Source})",
                    site.Domain, site.Category, site.Score, threshold, site.Hits, source);
            }
            else if (!site.IsBlocked)
            {
                var blocked = await BlockSiteAsync(site.Domain, config,
                    $"{site.Category} score={site.Score} hits={site.Hits} ({source})");
                if (blocked)
                {
                    site.IsBlocked = true;
                    _logger.LogWarning("[BLOQUEIO] {Domain} BLOQUEADO (cat={Category}, score={Score}>={Threshold}, hits={Hits}, {Source})",
                        site.Domain, site.Category, site.Score, threshold, site.Hits, source);
                }
            }
        }
        else
        {
            // Ainda abaixo do limite -> AVISO (confianca subindo; bloqueia ao reincidir)
            _logger.LogWarning("[AVISO] {Domain} (cat={Category}, score={Score}/{Threshold}, hits={Hits}, {Source}) - bloqueia ao reincidir",
                site.Domain, site.Category, site.Score, threshold, site.Hits, source);
            site.Warned = true;
        }

        _cache.Set(site);
        MarkDomainDone(site.Domain);
    }

    /// <summary>
    /// Verifica se o nome base do dominio corresponde a algum dominio já bloqueado.
    /// Verifica tanto config.BlockedSites quanto o arquivo hosts (para domínios adicionados manualmente).
    /// Ex: "chaturbate.lat" é bloqueado se "chaturbate.com" já está na lista.
    /// </summary>
    private static bool IsDomainNameAlreadyBlocked(string domain, AppConfig config)
    {
        var domainName = GetDomainName(domain);
        if (string.IsNullOrEmpty(domainName) || domainName.Length < 4)
            return false; // Nomes muito curtos geram falsos positivos

        // Verifica config + hosts file para cobrir domínios adicionados manualmente
        var allBlocked = new HashSet<string>(config.BlockedSites, StringComparer.OrdinalIgnoreCase);
        foreach (var hostsSite in HostsService.GetBlockedSites())
        {
            allBlocked.Add(hostsSite);
        }

        foreach (var blocked in allBlocked)
        {
            var blockedName = GetDomainName(blocked);
            if (!string.IsNullOrEmpty(blockedName) &&
                domainName.Equals(blockedName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Extrai o nome principal do dominio sem TLD.
    /// Ex: "chaturbate.com" -> "chaturbate", "xvideos.com.br" -> "xvideos"
    /// </summary>
    private static string GetDomainName(string domain)
    {
        var baseDomain = GetBaseDomain(domain);
        var parts = baseDomain.Split('.');
        if (parts.Length < 2) return baseDomain;

        // Trata TLDs compostos (.com.br, .co.uk)
        if (parts.Length >= 3 &&
            (parts[^2] == "com" || parts[^2] == "co" || parts[^2] == "org" || parts[^2] == "gov"))
        {
            return parts[^3];
        }

        return parts[0];
    }

    /// <summary>
    /// Adiciona site a lista de bloqueados
    /// </summary>
    /// <returns>true se o bloqueio foi realizado, false se estava em DryRun</returns>
    private async Task<bool> BlockSiteAsync(string domain, AppConfig config, string reason)
    {
        if (config.DryRun)
        {
            _logger.LogInformation("[DRY-RUN] Bloquearia: {Domain} ({Reason})", domain, reason);
            return false;
        }

        // Adiciona ao store de bloqueio (DNS proxy)
        _blockedStore.Add(domain);

        // Adiciona a config se nao estiver la
        if (!config.BlockedSites.Contains(domain, StringComparer.OrdinalIgnoreCase))
        {
            config.BlockedSites.Add(domain);
            config.Save();
        }

        _logger.LogWarning("Site bloqueado automaticamente: {Domain} (Motivo: {Reason})", domain, reason);

        // Notifica o usuario via Event Log
        try
        {
            using var eventLog = new System.Diagnostics.EventLog("Application");
            eventLog.Source = "FocusGuard";
            eventLog.WriteEntry(
                $"Site bloqueado automaticamente: {domain}\nMotivo: {reason}",
                EventLogEntryType.Warning);
        }
        catch
        {
            // Ignora se nao conseguir escrever no event log
        }

        await Task.CompletedTask;
        return true;
    }

    /// <summary>
    /// Sincroniza sites que foram detectados durante DryRun mas nao foram efetivamente bloqueados
    /// </summary>
    private async Task SyncCachedBlockedSitesAsync(AppConfig config)
    {
        try
        {
            // Busca sites com score alto que nao foram bloqueados (detectados em DryRun)
            var pendingBlock = _cache.GetSitesPendingBlock(config.ContentAnalysisThreshold);
            var configBlocked = config.BlockedSites;
            var hostsBlocked = HostsService.GetBlockedSites();

            var toSync = pendingBlock
                .Where(s => !configBlocked.Contains(s.Domain, StringComparer.OrdinalIgnoreCase) &&
                           !hostsBlocked.Contains(s.Domain, StringComparer.OrdinalIgnoreCase) &&
                           !IsWhitelisted(s.Domain))
                .ToList();

            if (toSync.Count > 0)
            {
                _logger.LogWarning("Encontrados {Count} sites detectados em DryRun que nao foram bloqueados. Sincronizando...", toSync.Count);

                foreach (var site in toSync)
                {
                    _logger.LogInformation("Bloqueando site do cache: {Domain} (Score: {Score}, Categoria: {Category})",
                        site.Domain, site.Score, site.Category);

                    if (await BlockSiteAsync(site.Domain, config, $"cache sync - {site.Category}"))
                    {
                        site.IsBlocked = true;
                        _cache.Set(site);
                    }
                }

                _cache.Save();
                _logger.LogInformation("Sincronizacao de cache concluida: {Count} sites bloqueados", toSync.Count);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao sincronizar sites do cache");
        }
    }

    // Funciona em ingles (Record Name) e portugues (Nome do Registro)
    [GeneratedRegex(@"(?:Record Name|Nome do Registro)[\s\.]+:\s+([^\r\n]+)", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex DnsCacheRegex();
}
