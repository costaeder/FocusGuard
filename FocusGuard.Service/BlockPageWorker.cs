using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using FocusGuard.Shared.Models;
using FocusGuard.Shared.Services;

namespace FocusGuard.Service;

/// <summary>
/// Worker que serve uma página de bloqueio nas portas 80 (HTTP) e 443 (HTTPS).
/// Gera um Root CA próprio, instala no Windows Trusted Root Store, e cria
/// certificados dinamicamente por domínio via SNI para HTTPS funcionar sem avisos.
/// </summary>
public partial class BlockPageWorker : BackgroundService
{
    private readonly ILogger<BlockPageWorker> _logger;
    private readonly BlockedDomainStore _blockedStore;
    private X509Certificate2? _rootCaCert;
    private readonly ConcurrentDictionary<string, X509Certificate2> _domainCerts = new();
    private readonly SemaphoreSlim _connectionLimiter = new(20, 20);
    private const int MaxCachedCerts = 200;

    private static readonly string CertDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "FocusGuard", "certs");

    private static readonly string RootCaPath = Path.Combine(CertDir, "rootca.pfx");
    private const string RootCaPassword = "FocusGuardCA2024";

    public BlockPageWorker(ILogger<BlockPageWorker> logger, BlockedDomainStore blockedStore)
    {
        _logger = logger;
        _blockedStore = blockedStore;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            EnsureRootCaCertificate();
            _logger.LogInformation("BlockPage: Root CA inicializado");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BlockPage: Erro ao inicializar Root CA, servidor de bloqueio desabilitado");
            return;
        }

        var httpTask = RunListener(80, false, stoppingToken);
        var httpsTask = RunListener(443, true, stoppingToken);

        await Task.WhenAll(httpTask, httpsTask);
    }

    private async Task RunListener(int port, bool useTls, CancellationToken ct)
    {
        TcpListener? listener = null;
        try
        {
            listener = new TcpListener(IPAddress.IPv6Any, port);
            listener.Server.DualMode = true;
            listener.Start();
            _logger.LogInformation("BlockPage: {Protocol} listener iniciado na porta {Port}",
                useTls ? "HTTPS" : "HTTP", port);

            while (!ct.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(ct);
                if (_connectionLimiter.CurrentCount == 0)
                {
                    // Muitas conexoes simultaneas - descarta para nao estressar o kernel
                    client.Dispose();
                    continue;
                }
                _ = Task.Run(async () =>
                {
                    await _connectionLimiter.WaitAsync(CancellationToken.None);
                    try { await HandleClientAsync(client, useTls); }
                    finally { _connectionLimiter.Release(); }
                }, CancellationToken.None);
            }
        }
        catch (OperationCanceledException) { }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
        {
            _logger.LogWarning("BlockPage: Porta {Port} já está em uso, listener {Protocol} desabilitado",
                port, useTls ? "HTTPS" : "HTTP");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BlockPage: Erro no listener porta {Port}", port);
        }
        finally
        {
            listener?.Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, bool useTls)
    {
        try
        {
            using (client)
            {
                client.ReceiveTimeout = 5000;
                client.SendTimeout = 5000;

                var networkStream = client.GetStream();

                if (useTls)
                {
                    using var sslStream = new SslStream(networkStream, false);

                    var sslOptions = new SslServerAuthenticationOptions
                    {
                        ServerCertificateSelectionCallback = (sender, hostName) =>
                            GetOrCreateDomainCert(hostName),
                        ClientCertificateRequired = false,
                        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    };

                    await sslStream.AuthenticateAsServerAsync(sslOptions);
                    await ServeBlockPageAsync(sslStream);
                }
                else
                {
                    await ServeBlockPageAsync(networkStream);
                }
            }
        }
        catch (AuthenticationException)
        {
            // Client rejeitou o certificado ou TLS handshake falhou - normal
        }
        catch (IOException)
        {
            // Conexão fechada pelo client - normal
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "BlockPage: Erro ao processar request");
        }
    }

    private async Task ServeBlockPageAsync(Stream stream)
    {
        // Lê os headers do HTTP request
        var buffer = new byte[8192];
        var bytesRead = await stream.ReadAsync(buffer);

        if (bytesRead == 0) return;

        var request = Encoding.UTF8.GetString(buffer, 0, bytesRead);

        // Extrai Host header
        var hostMatch = HostRegex().Match(request);
        var hostname = hostMatch.Success ? hostMatch.Groups[1].Value.Trim() : "site bloqueado";

        // Detecta URLs/dominios embutidos como parametro (bypass via web proxy).
        // So e visivel aqui porque o site ja esta bloqueado e caiu no nosso listener.
        DetectEmbeddedTargets(hostname, request);

        // Sites da categoria "cota diaria" so caem aqui quando o limite do dia
        // ja foi atingido -> mostra mensagem especifica.
        var isLimited = IsLimitedHost(hostname);

        // Monta e envia a resposta HTTP
        var html = GetBlockPageHtml(hostname, isLimited);
        var htmlBytes = Encoding.UTF8.GetBytes(html);

        var responseHeader =
            $"HTTP/1.1 200 OK\r\n" +
            $"Content-Type: text/html; charset=utf-8\r\n" +
            $"Content-Length: {htmlBytes.Length}\r\n" +
            $"Connection: close\r\n" +
            $"Cache-Control: no-store\r\n" +
            $"X-FocusGuard: blocked\r\n" +
            $"\r\n";

        await stream.WriteAsync(Encoding.ASCII.GetBytes(responseHeader));
        await stream.WriteAsync(htmlBytes);
        await stream.FlushAsync();
    }

    #region Certificados

    private void EnsureRootCaCertificate()
    {
        if (!Directory.Exists(CertDir))
            Directory.CreateDirectory(CertDir);

        // Tenta carregar Root CA existente do disco
        if (File.Exists(RootCaPath))
        {
            try
            {
                _rootCaCert = X509CertificateLoader.LoadPkcs12FromFile(RootCaPath, RootCaPassword,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

                if (_rootCaCert.HasPrivateKey)
                {
                    EnsureRootCaInStore();
                    _logger.LogInformation("BlockPage: Root CA carregado do disco (Thumbprint: {Thumbprint})",
                        _rootCaCert.Thumbprint[..8]);
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "BlockPage: Root CA existente inválido, gerando novo...");
            }
        }

        GenerateRootCaCertificate();
    }

    private void GenerateRootCaCertificate()
    {
        using var rsa = RSA.Create(4096);
        var dn = new X500DistinguishedName("CN=FocusGuard Root CA, O=FocusGuard, C=BR");

        var req = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Extensões de CA
        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature,
                true));
        req.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(10));

        // Exporta e reimporta para garantir acesso à chave privada
        var pfxBytes = cert.Export(X509ContentType.Pfx, RootCaPassword);
        _rootCaCert = X509CertificateLoader.LoadPkcs12(pfxBytes, RootCaPassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

        // Salva no disco
        File.WriteAllBytes(RootCaPath, pfxBytes);

        // Instala no Trusted Root Store
        EnsureRootCaInStore();

        _logger.LogInformation("BlockPage: Novo Root CA gerado e instalado (Thumbprint: {Thumbprint})",
            _rootCaCert.Thumbprint[..8]);
    }

    private void EnsureRootCaInStore()
    {
        if (_rootCaCert == null) return;

        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            // Remove CAs antigos do FocusGuard (se houver com thumbprint diferente)
            var oldCerts = store.Certificates.Find(
                X509FindType.FindBySubjectName, "FocusGuard Root CA", false);
            foreach (var old in oldCerts)
            {
                if (old.Thumbprint != _rootCaCert.Thumbprint)
                {
                    store.Remove(old);
                    _logger.LogInformation("BlockPage: Root CA antigo removido da store");
                }
            }

            // Adiciona o atual se não estiver
            var found = store.Certificates.Find(
                X509FindType.FindByThumbprint, _rootCaCert.Thumbprint, false);
            if (found.Count == 0)
            {
                store.Add(_rootCaCert);
                _logger.LogInformation("BlockPage: Root CA adicionado ao Trusted Root Certificate Authorities");
            }

            store.Close();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "BlockPage: Erro ao instalar Root CA no store");
        }
    }

    private X509Certificate2 GetOrCreateDomainCert(string? hostname)
    {
        hostname = string.IsNullOrEmpty(hostname)
            ? "blocked.focusguard.local"
            : hostname.ToLowerInvariant();

        if (_domainCerts.TryGetValue(hostname, out var cached))
            return cached;

        if (_rootCaCert == null)
            throw new InvalidOperationException("Root CA não inicializado");

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            $"CN={hostname}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Subject Alternative Names
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName(hostname);
        sanBuilder.AddDnsName($"*.{hostname}");
        req.CertificateExtensions.Add(sanBuilder.Build());

        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

        var ekuOids = new OidCollection();
        ekuOids.Add(new Oid("1.3.6.1.5.5.7.3.1")); // TLS Server Auth
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekuOids, false));

        // Número serial aleatório
        var serialNumber = new byte[16];
        Random.Shared.NextBytes(serialNumber);
        serialNumber[0] &= 0x7F; // Garante positivo

        // Assina com o Root CA
        var cert = req.Create(
            _rootCaCert,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1),
            serialNumber);

        // Junta cert + chave privada
        var certWithKey = cert.CopyWithPrivateKey(rsa);

        // Exporta/reimporta para compatibilidade Windows com SslStream
        var pfxBytes = certWithKey.Export(X509ContentType.Pfx, "");
        var finalCert = X509CertificateLoader.LoadPkcs12(pfxBytes, "",
            X509KeyStorageFlags.Exportable);

        // Limita cache de certificados para nao consumir memoria indefinidamente
        if (_domainCerts.Count >= MaxCachedCerts)
        {
            // Remove metade dos certs mais antigos
            var toRemove = _domainCerts.Keys.Take(MaxCachedCerts / 2).ToList();
            foreach (var key in toRemove)
            {
                if (_domainCerts.TryRemove(key, out var old))
                    old.Dispose();
            }
        }

        _domainCerts[hostname] = finalCert;
        return finalCert;
    }

    #endregion

    /// <summary>
    /// Analisa a request line (ex.: "GET /?url=https://xvideos.com HTTP/1.1") em busca
    /// de dominios embutidos como parametro — tecnica classica de bypass via web proxy.
    /// Registra a tentativa no log e no Event Log. Se o destino embutido tambem estiver
    /// bloqueado, sinaliza com mais destaque. Nao interfere na resposta (best-effort).
    /// </summary>
    private void DetectEmbeddedTargets(string proxyHost, string request)
    {
        try
        {
            // Primeira linha do request = metodo + caminho/query + versao
            var lineEnd = request.IndexOfAny(['\r', '\n']);
            var requestLine = lineEnd > 0 ? request[..lineEnd] : request;

            // Decodifica percent-encoding (url%3A%2F%2F... -> url://...) para achar os alvos
            string decoded;
            try { decoded = Uri.UnescapeDataString(requestLine); }
            catch { decoded = requestLine; }

            var targets = EmbeddedDomainRegex().Matches(decoded)
                .Select(m => m.Groups[1].Value.Trim('.', '/').ToLowerInvariant())
                .Where(d => d.Contains('.') && d.Length >= 4 &&
                            !d.Equals(proxyHost, StringComparison.OrdinalIgnoreCase))
                .Distinct()
                .Take(5)
                .ToList();

            if (targets.Count == 0) return;

            var blocked = targets.Where(_blockedStore.IsBlocked).ToList();
            var alvos = string.Join(", ", targets);

            if (blocked.Count > 0)
            {
                _logger.LogWarning(
                    "[PROXY-PARAM] BYPASS via {ProxyHost} -> destino BLOQUEADO embutido: {Blocked} (todos: {Targets})",
                    proxyHost, string.Join(", ", blocked), alvos);
            }
            else
            {
                _logger.LogWarning(
                    "[PROXY-PARAM] Acesso via {ProxyHost} com destino embutido na URL: {Targets}",
                    proxyHost, alvos);
            }

            try
            {
                using var eventLog = new System.Diagnostics.EventLog("Application") { Source = "FocusGuard" };
                var detalhe = blocked.Count > 0
                    ? $"Destino(s) BLOQUEADO(S) na URL: {string.Join(", ", blocked)}"
                    : $"Destino(s) na URL: {alvos}";
                eventLog.WriteEntry(
                    $"Tentativa de bypass via web proxy detectada.\nProxy: {proxyHost}\n{detalhe}",
                    System.Diagnostics.EventLogEntryType.Warning);
            }
            catch { /* Event Log indisponivel - ignora */ }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "BlockPage: erro ao detectar destino embutido");
        }
    }

    /// <summary>Verifica se o host pertence a categoria "cota diaria" (config.LimitedSites).</summary>
    private static bool IsLimitedHost(string hostname)
    {
        try
        {
            var host = hostname.Trim().ToLowerInvariant();
            foreach (var site in AppConfig.Load().LimitedSites)
            {
                var s = site.Trim().ToLowerInvariant();
                if (host.Equals(s) || host.EndsWith("." + s))
                    return true;
            }
        }
        catch { }
        return false;
    }

    #region HTML

    private static string GetBlockPageHtml(string hostname, bool isLimited = false)
    {
        var safeHostname = WebEncode(hostname);
        var titulo = isLimited ? "Limite diário atingido" : "Mantenha o Foco";
        var mensagem = isLimited
            ? "Você já usou todo o seu tempo diário neste site. O acesso será liberado novamente amanhã."
            : "Este site foi bloqueado pelo FocusGuard para ajudar a manter sua produtividade e bem-estar.";
        return $$"""
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>FocusGuard</title>
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
                        color: white;
                        height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        overflow: hidden;
                    }
                    .container {
                        text-align: center;
                        max-width: 560px;
                        padding: 40px;
                        animation: fadeIn 0.5s ease;
                    }
                    .shield {
                        width: 110px;
                        height: 110px;
                        margin: 0 auto 30px;
                        background: linear-gradient(135deg, #667eea, #764ba2);
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        box-shadow: 0 0 50px rgba(102, 126, 234, 0.35);
                    }
                    .shield svg {
                        width: 56px;
                        height: 56px;
                        fill: white;
                    }
                    h1 {
                        font-size: 2.2em;
                        margin-bottom: 14px;
                        font-weight: 700;
                        background: linear-gradient(90deg, #a78bfa, #818cf8);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                    }
                    p {
                        font-size: 1.1em;
                        opacity: 0.8;
                        line-height: 1.7;
                        margin-bottom: 28px;
                    }
                    .domain {
                        display: inline-block;
                        padding: 10px 24px;
                        background: rgba(255,255,255,0.06);
                        border: 1px solid rgba(255,255,255,0.12);
                        border-radius: 10px;
                        font-family: 'Cascadia Code', 'Consolas', monospace;
                        font-size: 0.9em;
                        color: #94a3b8;
                        letter-spacing: 0.3px;
                    }
                    .footer {
                        margin-top: 48px;
                        font-size: 0.8em;
                        opacity: 0.3;
                        letter-spacing: 1px;
                        text-transform: uppercase;
                    }
                    @keyframes fadeIn {
                        from { opacity: 0; transform: translateY(16px); }
                        to { opacity: 1; transform: translateY(0); }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="shield">
                        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
                        </svg>
                    </div>
                    <h1>{{titulo}}</h1>
                    <p>{{mensagem}}</p>
                    <div class="domain">{{safeHostname}}</div>
                    <div class="footer">FocusGuard</div>
                </div>
            </body>
            </html>
            """;
    }

    private static string WebEncode(string text)
    {
        return text
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;");
    }

    #endregion

    [GeneratedRegex(@"Host:\s*([^\r\n:]+)", RegexOptions.IgnoreCase)]
    private static partial Regex HostRegex();

    // Captura um dominio que aparece depois de "://" (scheme) ou depois de um
    // parametro de query ("?nome=" / "&nome="). Cobre url=, ref=, u=, q=, target= etc.
    [GeneratedRegex(@"(?:https?://|[?&][a-z0-9_]{1,12}=)([a-z0-9-]+(?:\.[a-z0-9-]+)+)", RegexOptions.IgnoreCase)]
    private static partial Regex EmbeddedDomainRegex();
}
